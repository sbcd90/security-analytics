/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.randomDetectorRule;

public class DetectorInputTests extends OpenSearchTestCase {

    public void testDetectorRuleAsTemplateArgs() {
        DetectorRule rule = randomDetectorRule();

        Map<String, Object> templateArgs = rule.asTemplateArg();

        Assert.assertEquals("Template args 'id' field does not match:", templateArgs.get(DetectorRule.RULE_ID_FIELD), rule.getId());
        assertEquals("Template args 'rule' field does not match:", templateArgs.get(DetectorRule.RULE_FIELD), rule.getRule());
        assertEquals("Template args 'name' field does not match:", templateArgs.get(DetectorRule.NAME_FIELD), rule.getName());
        assertEquals("Template args 'tags' field does not match:", templateArgs.get(DetectorRule.TAGS_FIELD), rule.getTags());
    }
}