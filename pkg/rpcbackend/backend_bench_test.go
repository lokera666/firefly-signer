// Copyright © 2026 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rpcbackend

import (
	"context"
	"testing"

	"github.com/hyperledger-firefly/common/pkg/metric"
)

func benchmarkReserveConcurrencySlot(b *testing.B, slots int64, metricsOn, parallel bool) {
	rpcMetrics = nil
	if metricsOn {
		EnableMetrics(context.Background(), metric.NewPrometheusMetricsRegistry(b.Name()))
		b.Cleanup(func() { rpcMetrics = nil })
	}
	rc := &RPCClient{concurrencySlots: make(chan bool, slots)}
	ctx := context.Background()
	acquireRelease := func() {
		returnSlot, rpcErr := rc.reserveConcurrencySlot(ctx, "bench")
		if rpcErr != nil {
			b.Fatal(rpcErr)
		}
		returnSlot()
	}

	b.ReportAllocs()
	b.ResetTimer()
	if parallel {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				acquireRelease()
			}
		})
		return
	}
	for i := 0; i < b.N; i++ {
		acquireRelease()
	}
}

func BenchmarkReserveConcurrencySlotUncontendedMetricsOff(b *testing.B) {
	benchmarkReserveConcurrencySlot(b, 50, false, false)
}

func BenchmarkReserveConcurrencySlotUncontendedMetricsOn(b *testing.B) {
	benchmarkReserveConcurrencySlot(b, 50, true, false)
}

func BenchmarkReserveConcurrencySlotContendedMetricsOn(b *testing.B) {
	benchmarkReserveConcurrencySlot(b, 1, true, true)
}
