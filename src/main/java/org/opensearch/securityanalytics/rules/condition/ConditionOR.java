/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.condition;

import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.ArrayList;
import java.util.List;

public class ConditionOR extends ConditionItem {

    private int argCount;
    private boolean operator;

    public ConditionOR(boolean tokenList,
                       List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args) {
        super(2, tokenList, args);
        this.argCount = 2;
        this.operator = true;
    }

    public static ConditionOR fromParsed(List<String> t) {
        List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args = new ArrayList<>();
        t.forEach(s -> args.add(Either.right(s)));
        return new ConditionOR(false, args);
    }
}