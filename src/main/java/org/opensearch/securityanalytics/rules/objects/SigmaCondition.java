/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.condition.ConditionIdentifier;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.utils.Either;


import java.util.Collections;

public class SigmaCondition {

    private String condition;

    private SigmaDetections detections;

    public SigmaCondition(String condition, SigmaDetections detections) {
        this.condition = condition;
        this.detections = detections;
    }

    public ConditionItem parsed() throws SigmaConditionError {
        if (condition.matches("[a-zA-Z0-9-_]+")) {
            ConditionIdentifier conditionIdentifier =
                    new ConditionIdentifier(Collections.singletonList(Either.right(condition)));
            return conditionIdentifier.postProcess(detections, null);
        }
        return null;
    }

}