// Package unixsocket implements a Unix domain socket transport for goflow2.
// It provides reliable delivery by buffering messages in an internal queue
// and automatically reconnecting on connection loss.
package unixsocket

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/netsampler/goflow2/v3/transport"
)

type msg struct {
	data []byte
}

// UnixSocketDriver sends formatted messages to a Unix domain stream socket.
type UnixSocketDriver struct {
	fieldsWhitelist string
	socketPath      string
	lineSeparator   string
	queueSize       int

	lock   sync.RWMutex
	conn   net.Conn
	writer io.Writer

	msgCh chan msg
	done  chan struct{}
	wg    sync.WaitGroup

	reloadCh chan os.Signal
}

// Prepare registers command-line flags.
func (d *UnixSocketDriver) Prepare() error {
	flag.StringVar(&d.socketPath, "transport.unixsocket", "", "Unix domain socket path")
	flag.StringVar(&d.lineSeparator, "transport.unixsocket.sep", "\n", "Line separator")
	flag.IntVar(&d.queueSize, "transport.unixsocket.queue", 10000, "Internal message queue size")
	flag.StringVar(&d.fieldsWhitelist, "transport.unixsocket.fields", "", "Comma-separated list of fields to keep (empty = all)")
	return nil
}

func filterFields(data []byte, whitelist string) ([]byte, error) {
	if whitelist == "" {
		return data, nil
	}
	allowed := make(map[string]bool)
	for _, f := range strings.Split(whitelist, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			allowed[f] = true
		}
	}
	var event map[string]interface{}
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	// всегда оставляем tcp_flags_str, если есть
	if _, exists := event["tcp_flags_str"]; exists {
		allowed["tcp_flags_str"] = true
	}
	for k := range event {
		if !allowed[k] {
			delete(event, k)
		}
	}
	return json.Marshal(event)
}

// connect establishes a new connection and updates the writer.
func (d *UnixSocketDriver) connect() error {
	if d.socketPath == "" {
		return fmt.Errorf("unixsocket: path not set")
	}

	conn, err := net.Dial("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("unixsocket: dial %s: %w", d.socketPath, err)
	}

	d.lock.Lock()
	if d.conn != nil {
		d.conn.Close()
	}
	d.conn = conn
	d.writer = conn
	d.lock.Unlock()

	log.Printf("[unixsocket] connected to %s", d.socketPath)
	return nil
}

// runWorker is a background goroutine that writes messages to the socket.
func (d *UnixSocketDriver) runWorker() {
	defer d.wg.Done()

	for {
		select {
		case m, ok := <-d.msgCh:
			if !ok {
				return
			}
			if err := d.writeMessage(m.data); err != nil {
				log.Printf("[unixsocket] write error: %v", err)
				if d.reconnect() {
					// Retry once after successful reconnect.
					if err := d.writeMessage(m.data); err != nil {
						log.Printf("[unixsocket] retry write after reconnect failed: %v", err)
					}
				} else {
					log.Printf("[unixsocket] reconnect failed, message dropped")
				}
			}
		case <-d.done:
			return
		}
	}
}

// writeMessage sends data + separator to the current writer.
func (d *UnixSocketDriver) writeMessage(data []byte) error {
	d.lock.RLock()
	w := d.writer
	d.lock.RUnlock()

	if w == nil {
		return fmt.Errorf("unixsocket: no connection")
	}

	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("write data: %w", err)
		}
	}
	if d.lineSeparator != "" {
		if _, err := w.Write([]byte(d.lineSeparator)); err != nil {
			return fmt.Errorf("write separator: %w", err)
		}
	}
	return nil
}

// reconnect closes the existing connection and retries with exponential backoff.
// Returns true if a new connection was established.
func (d *UnixSocketDriver) reconnect() bool {
	d.lock.Lock()
	if d.conn != nil {
		d.conn.Close()
		d.conn = nil
		d.writer = nil
	}
	d.lock.Unlock()

	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-d.done:
			return false
		default:
			if err := d.connect(); err == nil {
				return true
			}
			log.Printf("[unixsocket] reconnect failed, retrying in %v", backoff)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// Init starts the background writer and signal handler.
func (d *UnixSocketDriver) Init() error {
	if d.socketPath == "" {
		return fmt.Errorf("unixsocket: socket path is required")
	}

	if err := d.connect(); err != nil {
		return err
	}

	d.done = make(chan struct{})
	d.msgCh = make(chan msg, d.queueSize)

	d.wg.Add(1)
	go d.runWorker()

	// Handle SIGHUP for manual reconnect (similar to file driver).
	d.reloadCh = make(chan os.Signal, 1)
	signal.Notify(d.reloadCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case _, ok := <-d.reloadCh:
				if !ok {
					return
				}
				log.Printf("[unixsocket] received SIGHUP, forcing reconnect")
				d.reconnect()
			case <-d.done:
				return
			}
		}
	}()

	return nil
}

var tcpFlagNames = []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}

func tcpFlagsToString(flagsVal uint8) string {
	if flagsVal == 0 {
		return "NONE"
	}
	var parts []string
	for i := 0; i < 8; i++ {
		if flagsVal&(1<<i) != 0 {
			parts = append(parts, tcpFlagNames[i])
		}
	}
	return strings.Join(parts, "-")
}

// enrichJSON парсит JSON, добавляет tcp_flags_str и возвращает новый JSON.
func enrichJSON(data []byte) ([]byte, error) {
	var event map[string]interface{}
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	// Ищем поле tcp_flags (может быть int или float64 после JSON)
	if val, ok := event["tcp_flags"]; ok {
		var flagsVal uint8
		switch v := val.(type) {
		case float64:
			flagsVal = uint8(v)
		case int:
			flagsVal = uint8(v)
		default:
			// неизвестный тип, пропускаем
			return data, nil
		}
		event["tcp_flags_str"] = tcpFlagsToString(flagsVal)
	}
	newData, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return newData, nil
}

// Send enqueues a message for delivery. It blocks if the queue is full,
// providing backpressure upstream.
func (d *UnixSocketDriver) Send(key, data []byte) error {
	// Обогащаем JSON полем tcp_flags_str
	enriched, err := enrichJSON(data)
	if err != nil {
		log.Printf("[unixsocket] enrich error: %v", err)
		enriched = data // fallback to original
	}
	filtered, err := filterFields(enriched, d.fieldsWhitelist)
	if err != nil {
		log.Printf("[unixsocket] filter error: %v", err)
		filtered = enriched
	}
	m := msg{data: make([]byte, len(filtered))}
	copy(m.data, filtered)

	select {
	case d.msgCh <- m:
		return nil
	case <-d.done:
		return fmt.Errorf("unixsocket: driver is closed")
	}
}

// Close shuts down the worker, closes the connection, and removes the signal handler.
func (d *UnixSocketDriver) Close() error {
	if d.done != nil {
		close(d.done)
	}

	// Stop signal handler
	if d.reloadCh != nil {
		signal.Stop(d.reloadCh)
		close(d.reloadCh)
		d.reloadCh = nil
	}

	// Close channel and wait for worker to finish
	if d.msgCh != nil {
		close(d.msgCh)
	}
	d.wg.Wait()

	d.lock.Lock()
	defer d.lock.Unlock()
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

func init() {
	d := &UnixSocketDriver{}
	transport.RegisterTransportDriver("unixsocket", d)
}
