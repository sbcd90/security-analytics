/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.List;

public class SigmaStartswithModifier extends SigmaValueModifier {

    public SigmaStartswithModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }

    @Override
    public Pair<Class<?>, Class<?>> getTypeHints() {
        return Pair.of(SigmaString.class, null);
    }

    @Override
    public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) {
        if (val.isLeft() && val.getLeft() instanceof SigmaString) {
            SigmaString value = (SigmaString) val.getLeft();
            if (!value.endsWith(Either.right(SigmaString.SpecialChars.WILDCARD_MULTI))) {
                value.append(AnyOneOf.middleVal(SigmaString.SpecialChars.WILDCARD_MULTI));
            }
            val = Either.left(value);
            return val;
        } else if (val.isLeft() && val.getLeft() instanceof SigmaRegularExpression) {

        }
        return null;
    }
}