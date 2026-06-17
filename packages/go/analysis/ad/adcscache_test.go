// Copyright 2024 Specter Ops, Inc.
//
// Licensed under the Apache License, Version 2.0
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
//
// SPDX-License-Identifier: Apache-2.0

package ad

import (
	"testing"

	"github.com/specterops/bloodhound/packages/go/graphschema/ad"
	"github.com/specterops/dawgs/cardinality"
	"github.com/specterops/dawgs/graph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func duplexOf(ids ...graph.ID) cardinality.Duplex[uint64] {
	bitmap := cardinality.NewBitmap64()
	for _, id := range ids {
		bitmap.Add(id.Uint64())
	}
	return bitmap
}

// newForestFilterCache builds an ADCSCache where the CA has a valid cert chain to
// both domains, so only forest scoping can distinguish them. Each test sets the
// forest-scoping fields itself.
func newForestFilterCache(eca, inForestDomain, foreignDomain *graph.Node) *ADCSCache {
	cache := NewADCSCache()

	cache.enterpriseCertAuthorities = []*graph.Node{eca}
	cache.domains = []*graph.Node{inForestDomain, foreignDomain}

	for _, domain := range cache.domains {
		cache.rootCAForChainValid[domain.ID] = duplexOf(eca.ID)
		cache.authStoreForChainValid[domain.ID] = duplexOf(eca.ID)
	}

	return cache
}

func adcsForestFilterNodes() (eca, inForestDomain, foreignDomain *graph.Node) {
	eca = graph.NewNode(10, graph.NewProperties(), ad.EnterpriseCA)
	inForestDomain = graph.NewNode(1, graph.NewProperties(), ad.Domain)
	foreignDomain = graph.NewNode(2, graph.NewProperties(), ad.Domain)
	return eca, inForestDomain, foreignDomain
}

func TestGetECAHostedChainedDomains_ForestScoping(t *testing.T) {
	t.Run("forest known: keeps in-forest domain, drops foreign-forest domain", func(t *testing.T) {
		eca, inForestDomain, foreignDomain := adcsForestFilterNodes()
		cache := newForestFilterCache(eca, inForestDomain, foreignDomain)

		cache.hasHostingComputer[eca.ID] = true
		cache.hasInForestHostingComputer[eca.ID] = true
		cache.ecaForestDomains[eca.ID] = duplexOf(inForestDomain.ID)

		result := cache.GetECAHostedChainedDomains()

		require.Contains(t, result, eca.ID.Uint64())
		chains := result[eca.ID.Uint64()]
		assert.True(t, chains.Domains.Contains(inForestDomain.ID.Uint64()), "in-forest domain should survive")
		assert.False(t, chains.Domains.Contains(foreignDomain.ID.Uint64()), "foreign-forest domain should be filtered out")
		assert.Equal(t, uint64(1), chains.Domains.Cardinality())
	})

	t.Run("forest known but only a cross-forest hosting computer: CA is dropped entirely", func(t *testing.T) {
		eca, inForestDomain, foreignDomain := adcsForestFilterNodes()
		cache := newForestFilterCache(eca, inForestDomain, foreignDomain)

		// A hosting computer exists, but it lives outside the CA's forest.
		cache.hasHostingComputer[eca.ID] = true
		cache.hasInForestHostingComputer[eca.ID] = false
		cache.ecaForestDomains[eca.ID] = duplexOf(inForestDomain.ID)

		result := cache.GetECAHostedChainedDomains()

		assert.NotContains(t, result, eca.ID.Uint64(), "CA with no in-forest host should be skipped")
	})

	t.Run("forest unknown: falls back to host-only gating with no domain filtering", func(t *testing.T) {
		eca, inForestDomain, foreignDomain := adcsForestFilterNodes()
		cache := newForestFilterCache(eca, inForestDomain, foreignDomain)

		// No ecaForestDomains / hasInForestHostingComputer entry => forest unknown.
		cache.hasHostingComputer[eca.ID] = true

		result := cache.GetECAHostedChainedDomains()

		require.Contains(t, result, eca.ID.Uint64())
		chains := result[eca.ID.Uint64()]
		assert.True(t, chains.Domains.Contains(inForestDomain.ID.Uint64()))
		assert.True(t, chains.Domains.Contains(foreignDomain.ID.Uint64()), "fallback should preserve prior behavior")
		assert.Equal(t, uint64(2), chains.Domains.Cardinality())
	})

	t.Run("forest unknown and no hosting computer: CA is dropped", func(t *testing.T) {
		eca, inForestDomain, foreignDomain := adcsForestFilterNodes()
		cache := newForestFilterCache(eca, inForestDomain, foreignDomain)

		// hasHostingComputer absent/false and forest unknown.

		result := cache.GetECAHostedChainedDomains()

		assert.NotContains(t, result, eca.ID.Uint64())
	})
}

func TestGetChainedDomains_ForestScoping(t *testing.T) {
	t.Run("forest filter applies without the hosting-computer guard", func(t *testing.T) {
		eca, inForestDomain, foreignDomain := adcsForestFilterNodes()
		cache := newForestFilterCache(eca, inForestDomain, foreignDomain)

		// GetChainedDomains intentionally ignores hosting computers, so leave them
		// unset to prove the forest filter alone scopes the EnrollOnBehalfOf linkage.
		cache.ecaForestDomains[eca.ID] = duplexOf(inForestDomain.ID)

		result := cache.GetChainedDomains()

		require.Contains(t, result, eca.ID.Uint64())
		chains := result[eca.ID.Uint64()]
		assert.True(t, chains.Domains.Contains(inForestDomain.ID.Uint64()))
		assert.False(t, chains.Domains.Contains(foreignDomain.ID.Uint64()), "foreign-forest domain should be filtered out")
	})

	t.Run("forest unknown: keeps every chained domain", func(t *testing.T) {
		eca, inForestDomain, foreignDomain := adcsForestFilterNodes()
		cache := newForestFilterCache(eca, inForestDomain, foreignDomain)

		result := cache.GetChainedDomains()

		require.Contains(t, result, eca.ID.Uint64())
		chains := result[eca.ID.Uint64()]
		assert.Equal(t, uint64(2), chains.Domains.Cardinality())
	})
}
