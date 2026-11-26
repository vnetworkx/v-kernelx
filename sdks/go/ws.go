package vnetworksdk

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
)

// SubscribeEvents opens a WebSocket stream to /v1/ws and invokes callback for each parsed JSON event.
func (c *Client) SubscribeEvents(callback func(map[string]any)) error {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return err
	}
	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)
	req := fmt.Sprintf(
		"GET /v1/ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		u.Host, wsKey,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return err
	}

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return err
		}
		if line == "\r\n" {
			break
		}
	}

	go func() {
		defer conn.Close()
		for {
			hdr := make([]byte, 2)
			if _, err := io.ReadFull(reader, hdr); err != nil {
				return
			}
			opcode := hdr[0] & 0x0F
			length := uint64(hdr[1] & 0x7F)
			if length == 126 {
				var ext uint16
				if err := binary.Read(reader, binary.BigEndian, &ext); err != nil {
					return
				}
				length = uint64(ext)
			} else if length == 127 {
				if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
					return
				}
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(reader, payload); err != nil {
				return
			}
			if opcode == 0x8 {
				return
			}
			if opcode == 0x1 {
				var evt map[string]any
				if json.Unmarshal(payload, &evt) == nil {
					callback(evt)
				}
			}
		}
	}()
	return nil
}
