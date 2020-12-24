// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os

import (
	"internal/poll"
	"io"
)

var pollCopyFileRange = poll.CopyFileRange

func (f *File) readFrom(r io.Reader) (written int64, handled bool, err error) {
	// copy_file_range(2) does not support destinations opened with
	// O_APPEND, so don't even try.
	if f.appendMode {
		return 0, false, nil
	}

	remain := int64(1 << 62)

	lr, ok := r.(*io.LimitedReader)
	if ok {
		remain, r = lr.N, lr.R
		if remain <= 0 {
			return 0, true, nil
		}
	}

	// compatible without code change to io.LimitWriter
	// just use io.LimitReader like this:
	// f := *os.File ...
	// conn := *net.TCPConn ...
	// io.Copy(f, io.LimitReader(conn, size))
	// but, avoid cycle import, can not use r.(*net.TCPConn)
	// just check io.WriterTo, because *File is not implement io.WriterTo
	// when r is a *File, copy file range is still ok.
	wt, ok := r.(io.WriterTo)
	if ok {
		w, e := wt.WriteTo(io.LimitWriter(f, remain))
		return w, true, e
	}

	src, ok := r.(*File)
	if !ok {
		return 0, false, nil
	}
	if src.checkValid("ReadFrom") != nil {
		// Avoid returning the error as we report handled as false,
		// leave further error handling as the responsibility of the caller.
		return 0, false, nil
	}

	written, handled, err = pollCopyFileRange(&f.pfd, &src.pfd, remain)
	if lr != nil {
		lr.N -= written
	}
	return written, handled, NewSyscallError("copy_file_range", err)
}
