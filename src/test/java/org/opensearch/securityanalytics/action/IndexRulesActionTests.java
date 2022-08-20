/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

public class IndexRulesActionTests extends OpenSearchTestCase {

    public void testIndexRulesActionName() {
        Assert.assertNotNull(IndexDetectorAction.INSTANCE.name());
        Assert.assertEquals(IndexDetectorAction.INSTANCE.name(), IndexDetectorAction.NAME);
    }
}