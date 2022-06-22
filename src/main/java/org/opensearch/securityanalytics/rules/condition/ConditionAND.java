/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.condition;

import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class ConditionAND extends ConditionItem {

    private int argCount;
    private boolean operator;

    public ConditionAND(boolean tokenList,
                        List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args) {
        super(2, tokenList, args);
        this.argCount = 2;
        this.operator = true;
    }

    public static ConditionAND fromParsed(List<String> t) {
        List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args = new ArrayList<>();
        t.forEach(s -> args.add(Either.right(s)));
        return new ConditionAND(false, args);
    }
}