/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.List;

public class SigmaContainsModifier extends SigmaValueModifier {

    public SigmaContainsModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }

    @Override
    public Either<Class<?>, Class<?>> getTypeHints() {
        return Either.left(SigmaString.class);
    }

    @Override
    public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) {
        if (val.isLeft() && val.getLeft() instanceof SigmaString) {
            SigmaString value = (SigmaString) val.getLeft();
            if (!value.startsWith(Either.right(SigmaString.SpecialChars.WILDCARD_MULTI))) {
                value.prepend(AnyOneOf.middleVal(SigmaString.SpecialChars.WILDCARD_MULTI));
            }
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