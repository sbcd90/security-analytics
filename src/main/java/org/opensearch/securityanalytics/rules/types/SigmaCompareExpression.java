/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

public class SigmaCompareExpression implements SigmaType {

    public class CompareOperators {
        public static final String LT = "<";
        public static final String LTE = "<=";
        public static final String GT = ">";
        public static final String GTE = ">=";
    }

    private SigmaNumber number;

    private CompareOperators op;
}