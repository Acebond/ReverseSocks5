package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

type frameHeader struct {
	id     uint32
	length uint16
	flags  uint16
}

const (
	frameHeaderSize = 4 + 2 + 2 // must be exact frameHeader struct size
	maxPayloadSize  = math.MaxUint16
)

const (
	flagData        = iota + 1 // data frame
	flagKeepalive              // empty frame to keep connection open
	flagOpenStream             // first frame in stream
	flagCloseStream            // stream is being closed gracefully
	flagCloseMux               // mux is being closed gracefully
)

func encodeFrameHeader(buf []byte, h frameHeader) {
	binary.LittleEndian.PutUint32(buf[0:], h.id)
	binary.LittleEndian.PutUint16(buf[4:], h.length)
	binary.LittleEndian.PutUint16(buf[6:], h.flags)
}

func decodeFrameHeader(buf []byte) frameHeader {
	return frameHeader{
		id:     binary.LittleEndian.Uint32(buf[0:]),
		length: binary.LittleEndian.Uint16(buf[4:]),
		flags:  binary.LittleEndian.Uint16(buf[6:]),
	}
}

// nextFrame reads and decrypts a frame from reader
func readFrame(reader io.Reader, frameBuf []byte) (frameHeader, []byte, error) {

	headerBuf := [frameHeaderSize]byte{}

	if _, err := io.ReadFull(reader, headerBuf[:]); err != nil {
		return frameHeader{}, nil, fmt.Errorf("could not read frame header: %w", err)
	}
	h := decodeFrameHeader(headerBuf[:])

	payloadSize := uint32(0)
	if h.flags == flagData {
		payloadSize += uint32(h.length)
	}

	if _, err := io.ReadFull(reader, frameBuf[:payloadSize]); err != nil {
		return frameHeader{}, nil, fmt.Errorf("could not read frame payload: %w", err)
	}

	return h, frameBuf[:h.length], nil
}

// appendFrame writs and encrypts a frame to buf
func appendFrame(buf []byte, h frameHeader, payload []byte) []byte {
	frame := buf[len(buf):][:frameHeaderSize+len(payload)]
	encodeFrameHeader(frame[:frameHeaderSize], h)
	copy(frame[frameHeaderSize:], payload)
	return buf[:len(buf)+len(frame)]
}
