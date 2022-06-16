/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public abstract class SigmaModifier {

    private SigmaDetectionItem detectionItem;

    private List<Class<? extends SigmaModifier>> appliedModifiers;

    public SigmaModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        this.detectionItem = detectionItem;
        this.appliedModifiers = appliedModifiers;
    }

    private boolean typeCheck(Either<SigmaType, List<SigmaType>> val) {
        Either<Class<?>, Class<?>> typePair = this.getTypeHints();
        return (typePair.isLeft() && val.getLeft() != null && typePair.getLeft().equals(val.getLeft().getClass())) ||
                (typePair.isRight() && val.getLeft() != null && typePair.get().equals(val.getLeft().getClass())) ||
                (typePair.isLeft() && val.get() != null && typePair.getLeft().equals(val.get().getClass())) ||
                (typePair.isRight() && val.get() != null && typePair.get().equals(val.get().getClass()));
    }

    public abstract Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) throws SigmaValueError, SigmaRegularExpressionError, SigmaTypeError;

    public abstract Either<Class<?>, Class<?>> getTypeHints();

    public List<SigmaType> apply(Either<SigmaType, List<SigmaType>> val) throws SigmaTypeError, SigmaValueError, SigmaRegularExpressionError {
        if (val.getLeft() instanceof SigmaExpansion) {
            List<SigmaType> values = new ArrayList<>();
            for (SigmaType value: ((SigmaExpansion) val.getLeft()).getValues()) {
                List<? extends SigmaType> va = this.apply(Either.left(value));
                values.addAll(va);
            }
            return Collections.singletonList(new SigmaExpansion(values));
        } else {
            if (!this.typeCheck(val)) {
                throw new SigmaTypeError("Modifier " + this.getClass().getName() + " incompatible to value type of '" + val + "'");
            }
            Either<SigmaType, List<SigmaType>> r = this.modify(val);
            if (r.isRight()) {
                return r.get();
            } else {
                return Collections.singletonList(r.getLeft());
            }
        }
    }

    public SigmaDetectionItem getDetectionItem() {
        return detectionItem;
    }

    public List<Class<? extends SigmaModifier>> getAppliedModifiers() {
        return appliedModifiers;
    }
}