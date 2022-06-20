/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.condition.*;
import org.opensearch.securityanalytics.rules.exceptions.*;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class SigmaDetection {

    private List<Either<SigmaDetectionItem, SigmaDetection>> detectionItems;
    private Either<Class<ConditionAND>, Class<ConditionOR>> itemLinking;

    private Either<ConditionItem, SigmaDetection> parent;
    private boolean operator;

    public SigmaDetection(List<Either<SigmaDetectionItem, SigmaDetection>> detectionItems,
                          Either<Class<ConditionAND>, Class<ConditionOR>> itemLinking) throws SigmaDetectionError {
        this.detectionItems = detectionItems;
        this.itemLinking = itemLinking == null? Either.left(ConditionAND.class): itemLinking;

        if (this.detectionItems.size() == 0) {
            throw new SigmaDetectionError("Detection is empty");
        }

        List<Class<?>> typeSet = new ArrayList<>();
        for (Either<SigmaDetectionItem, SigmaDetection> detectionItem: detectionItems) {
            if (detectionItem.isLeft()) {
                typeSet.add(SigmaDetectionItem.class);
            }
            if (detectionItem.isRight()) {
                typeSet.add(SigmaDetection.class);
            }
        }

        if (typeSet.contains(SigmaDetectionItem.class)) {
            this.itemLinking = Either.left(ConditionAND.class);
        } else {
            this.itemLinking = Either.right(ConditionOR.class);
        }
    }

    protected static SigmaDetection fromDefinition(Map<String, Object> definition) throws SigmaModifierError, SigmaDetectionError, SigmaValueError, SigmaRegularExpressionError {
        if (definition instanceof Map) {
            List<Either<SigmaDetectionItem, SigmaDetection>> detectionItems = new ArrayList<>();
            for (Map.Entry<String, Object> defEntry: definition.entrySet()) {
                Object val = defEntry.getValue();

                if (val instanceof Integer) {
                    detectionItems.add(Either.left(SigmaDetectionItem.fromMapping(defEntry.getKey(),
                            Either.left(AnyOneOf.leftVal((Integer) val)))));
                } else if (val instanceof Float) {
                    detectionItems.add(Either.left(SigmaDetectionItem.fromMapping(defEntry.getKey(),
                            Either.left(AnyOneOf.middleVal((Float) val)))));
                } else if (val instanceof String) {
                    detectionItems.add(Either.left(SigmaDetectionItem.fromMapping(defEntry.getKey(),
                            Either.left(AnyOneOf.rightVal(val.toString())))));
                } else if (val instanceof List) {
                    SigmaDetectionItem item =
                    SigmaDetectionItem.fromMapping(defEntry.getKey(), Either.right(((List<Object>) val).stream().map(
                            (Function<Object, AnyOneOf<Integer, Float, String>>) o -> {
                                if (o instanceof Integer) {
                                    return AnyOneOf.leftVal((Integer) o);
                                } else if (o instanceof Float) {
                                    return AnyOneOf.middleVal((Float) o);
                                } else if (o instanceof String) {
                                    return AnyOneOf.rightVal(o.toString());
                                }
                                return null;
                            }).collect(Collectors.toList())));
                    detectionItems.add(Either.left(item));
                }
            }
            return new SigmaDetection(detectionItems, null);
        }
        return null;
    }

    public AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression> postProcess(SigmaDetections detections, Object parent) throws SigmaConditionError {
        this.parent = parent instanceof ConditionItem? Either.left((ConditionItem) parent): Either.right((SigmaDetection)parent);

        List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> valueExpressions = new ArrayList<>();
        for (Either<SigmaDetectionItem, SigmaDetection> detectionItem: this.detectionItems) {
            if (detectionItem.isLeft()) {
                Either<Either<ConditionAND, ConditionOR>, Either<ConditionFieldEqualsValueExpression, ConditionValueExpression>> item =
                    detectionItem.getLeft().postProcess(detections, this);

                if (item.isLeft() && item.getLeft().isLeft()) {
                    valueExpressions.add(Either.left(AnyOneOf.leftVal(item.getLeft().getLeft())));
                } else if (item.isLeft() && item.getLeft().isRight()) {
                    valueExpressions.add(Either.left(AnyOneOf.leftVal(item.getLeft().get())));
                } else if (item.isRight() && item.get().isLeft()) {
                    valueExpressions.add(Either.left(AnyOneOf.middleVal(item.get().getLeft())));
                } else if (item.isRight() && item.get().isRight()) {
                    valueExpressions.add(Either.left(AnyOneOf.rightVal(item.get().get())));
                }
            }
        }

        if (valueExpressions.size() == 1) {
            return valueExpressions.get(0).getLeft();
        } else {
            if (itemLinking.isLeft()) {
                return AnyOneOf.leftVal(new ConditionAND(false, valueExpressions));
            } else if (itemLinking.isRight()) {
                return AnyOneOf.leftVal(new ConditionOR(false, valueExpressions));
            }
        }
        return null;
    }

    public List<Either<SigmaDetectionItem, SigmaDetection>> getDetectionItems() {
        return detectionItems;
    }

    public Either<Class<ConditionAND>, Class<ConditionOR>> getItemLinking() {
        return itemLinking;
    }
}