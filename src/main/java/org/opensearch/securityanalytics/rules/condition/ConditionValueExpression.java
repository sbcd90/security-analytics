/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.condition;

import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.objects.SigmaDetections;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

public class ConditionValueExpression {

    private SigmaType value;

    private Either<ConditionItem, SigmaDetectionItem> parent;
    private boolean operator;

    public ConditionValueExpression(SigmaType value) {
        this.value = value;
    }

    public ConditionValueExpression postProcess(SigmaDetections detections, Object parent) {
        this.parent = parent instanceof ConditionItem? Either.left((ConditionItem) parent): Either.right((SigmaDetectionItem) parent);
        return this;
    }

    public SigmaType getValue() {
        return value;
    }
}