/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;


import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;

import java.util.List;

public class SigmaLessThanModifier extends SigmaCompareModifier {

    public SigmaLessThanModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }
}