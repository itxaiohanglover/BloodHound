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

//go:build integration

package ad_test

import (
	"testing"

	"github.com/specterops/bloodhound/cmd/api/src/test/integration"
	"github.com/specterops/bloodhound/packages/go/graphschema"
	"github.com/specterops/bloodhound/packages/go/graphschema/ad"
	"github.com/specterops/bloodhound/packages/go/graphschema/common"
	"github.com/specterops/dawgs/graph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addEnabledHostingComputer creates an enabled computer in the given domain and
// links it to the CA via HostsCAService (mirrors the integration package's
// unexported addHostingComputer).
func addEnabledHostingComputer(testCtx *integration.GraphTestContext, name, domainSID string, enterpriseCA *graph.Node) {
	computer := testCtx.NewActiveDirectoryComputer(name, domainSID)
	computer.Properties.Set(common.Enabled.String(), true)
	testCtx.UpdateNode(computer)
	testCtx.NewRelationship(computer, enterpriseCA, ad.HostsCAService)
}

// linkEnterpriseCAToDomain adds the per-domain edges that make a domain "chain
// valid" (RootCAFor ∩ TrustedForNTAuth) for the CA. The per-CA EnterpriseCAFor
// edge is created once by the caller; each domain gets its own NTAuthStore so the
// TrustedForNTAuth edges don't collide.
func linkEnterpriseCAToDomain(testCtx *integration.GraphTestContext, enterpriseCA, rootCA *graph.Node, domain *graph.Node, domainSID string) {
	ntAuthStore := testCtx.NewActiveDirectoryNTAuthStore("NTAuthStore-"+domainSID, domainSID)

	// RootCAFor path: domain <-RootCAFor- rootCA <-EnterpriseCAFor- enterpriseCA
	testCtx.NewRelationship(rootCA, domain, ad.RootCAFor)

	// TrustedForNTAuth path: domain <-NTAuthStoreFor- ntAuthStore <-TrustedForNTAuth- enterpriseCA
	testCtx.NewRelationship(ntAuthStore, domain, ad.NTAuthStoreFor)
	testCtx.NewRelationship(enterpriseCA, ntAuthStore, ad.TrustedForNTAuth)
}

// TestADCSForestScoping_FiltersForeignForestDomain models shared ADCS across two
// forests: a CA hosted in forest A whose cert chain also reaches forest B's
// domain. The CA's hosting computer is in forest A, so the CA is retained but its
// chained-domain set must be scoped to forest A only.
func TestADCSForestScoping_FiltersForeignForestDomain(t *testing.T) {
	testContext := integration.NewGraphTestContext(t, graphschema.DefaultGraphSchema())

	var (
		domainASID = integration.RandomDomainSID()
		domainBSID = integration.RandomDomainSID()

		enterpriseCAID graph.ID
		domainAID      graph.ID
		domainBID      graph.ID
	)

	testContext.DatabaseTestWithSetup(
		func(harness *integration.HarnessDetails) error {
			domainA := testContext.NewActiveDirectoryDomain("ForestA-Domain", domainASID, false, true)
			domainB := testContext.NewActiveDirectoryDomain("ForestB-Domain", domainBSID, false, true)

			// The CA and its root live in forest A.
			enterpriseCA := testContext.NewActiveDirectoryEnterpriseCA("SharedECA", domainASID)
			rootCA := testContext.NewActiveDirectoryRootCA("SharedRootCA", domainASID)

			// The CA chains up to its root once; the per-domain edges are added below.
			testContext.NewRelationship(enterpriseCA, rootCA, ad.EnterpriseCAFor)

			// Valid cert chain to forest A (the CA's own forest)...
			linkEnterpriseCAToDomain(testContext, enterpriseCA, rootCA, domainA, domainASID)
			// ...and a cross-forest chain into forest B (shared ADCS).
			linkEnterpriseCAToDomain(testContext, enterpriseCA, rootCA, domainB, domainBSID)

			// Hosting computer lives in the CA's own forest.
			addEnabledHostingComputer(testContext, "HostA", domainASID, enterpriseCA)

			enterpriseCAID = enterpriseCA.ID
			domainAID = domainA.ID
			domainBID = domainB.ID
			return nil
		},
		func(harness integration.HarnessDetails, db graph.Database) {
			_, cache, err := FetchADCSPrereqs(db)
			require.NoError(t, err)

			chainedDomains := cache.GetECAHostedChainedDomains()

			require.Contains(t, chainedDomains, enterpriseCAID.Uint64(), "CA with an in-forest host should be retained")
			chains := chainedDomains[enterpriseCAID.Uint64()]
			assert.True(t, chains.Domains.Contains(domainAID.Uint64()), "in-forest domain should survive")
			assert.False(t, chains.Domains.Contains(domainBID.Uint64()), "foreign-forest domain should be filtered out")
		},
	)
}

// TestADCSForestScoping_DropsCAWithOnlyCrossForestHost models a CA whose only
// HostsCAService computer was matched across a forest boundary. With no hosting
// computer in the CA's own forest, the CA should be dropped entirely.
func TestADCSForestScoping_DropsCAWithOnlyCrossForestHost(t *testing.T) {
	testContext := integration.NewGraphTestContext(t, graphschema.DefaultGraphSchema())

	var (
		domainASID = integration.RandomDomainSID()
		domainBSID = integration.RandomDomainSID()

		enterpriseCAID graph.ID
	)

	testContext.DatabaseTestWithSetup(
		func(harness *integration.HarnessDetails) error {
			domainA := testContext.NewActiveDirectoryDomain("ForestA-Domain", domainASID, false, true)
			domainB := testContext.NewActiveDirectoryDomain("ForestB-Domain", domainBSID, false, true)

			enterpriseCA := testContext.NewActiveDirectoryEnterpriseCA("SharedECA", domainASID)
			rootCA := testContext.NewActiveDirectoryRootCA("SharedRootCA", domainASID)

			// The CA chains up to its root once; the per-domain edges are added below.
			testContext.NewRelationship(enterpriseCA, rootCA, ad.EnterpriseCAFor)

			linkEnterpriseCAToDomain(testContext, enterpriseCA, rootCA, domainA, domainASID)
			linkEnterpriseCAToDomain(testContext, enterpriseCA, rootCA, domainB, domainBSID)

			// Only hosting computer lives in forest B (cross-forest from the CA).
			addEnabledHostingComputer(testContext, "HostB", domainBSID, enterpriseCA)

			enterpriseCAID = enterpriseCA.ID
			return nil
		},
		func(harness integration.HarnessDetails, db graph.Database) {
			_, cache, err := FetchADCSPrereqs(db)
			require.NoError(t, err)

			chainedDomains := cache.GetECAHostedChainedDomains()

			assert.NotContains(t, chainedDomains, enterpriseCAID.Uint64(), "CA with no in-forest hosting computer should be skipped")
		},
	)
}
