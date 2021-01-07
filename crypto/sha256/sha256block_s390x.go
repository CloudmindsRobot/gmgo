// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha256

import "github.com/CloudmindsRobot/gmgo/internal/cpu"

var useAsm = cpu.S390X.HasSHA256
