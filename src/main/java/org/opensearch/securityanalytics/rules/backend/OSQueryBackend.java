/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.backend;

import org.opensearch.common.UUIDs;
import org.opensearch.commons.alerting.aggregation.bucketselectorext.BucketSelectorExtAggregationBuilder;
import org.opensearch.commons.alerting.model.BucketLevelTrigger;
import org.opensearch.script.Script;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.search.aggregations.metrics.AvgAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MaxAggregationBuilder;
import org.opensearch.search.aggregations.metrics.MinAggregationBuilder;
import org.opensearch.search.aggregations.metrics.SumAggregationBuilder;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.condition.ConditionAND;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionNOT;
import org.opensearch.securityanalytics.rules.condition.ConditionOR;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionType;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaBool;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.securityanalytics.rules.types.SigmaCompareExpression;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.apache.commons.lang3.NotImplementedException;

import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class OSQueryBackend extends QueryBackend {

    private String tokenSeparator;

    private String orToken;

    private String andToken;

    private String notToken;

    private String escapeChar;

    private String wildcardMulti;

    private String wildcardSingle;

    private String addEscaped;

    private String addReserved;

    private String eqToken;

    private String strQuote;

    private String reQuote;

    private List<String> reEscape;

    private String reEscapeChar;

    private String reExpression;

    private String cidrExpression;

    private String fieldNullExpression;

    private String unboundValueStrExpression;

    private String unboundValueNumExpression;

    private String unboundWildcardExpression;

    private String unboundReExpression;

    private String compareOpExpression;

    private int valExpCount;

    private String aggQuery;

    private String aggCountQuery;

    private String bucketTriggerQuery;

    private String bucketTriggerScript;

    private static final String groupExpression = "(%s)";
    private static final Map<String, String> compareOperators = Map.of(
            SigmaCompareExpression.CompareOperators.GT, "gt",
            SigmaCompareExpression.CompareOperators.GTE, "gte",
            SigmaCompareExpression.CompareOperators.LT, "lt",
            SigmaCompareExpression.CompareOperators.LTE, "lte"
    );

    private static final List<Class<?>> precedence = Arrays.asList(ConditionNOT.class, ConditionAND.class, ConditionOR.class);

    public OSQueryBackend(String ruleCategory, boolean collectErrors, boolean enableFieldMappings) throws IOException {
        super(ruleCategory, true, enableFieldMappings, true, collectErrors);
        this.tokenSeparator = " ";
        this.orToken = "OR";
        this.andToken = "AND";
        this.notToken = "NOT";
        this.escapeChar = "\\";
        this.wildcardMulti = "*";
        this.wildcardSingle = "?";
        this.addEscaped = "/:\\+-=><!(){}[]^\"~*?";
        this.addReserved = "&& ||";
        this.eqToken = ":";
        this.strQuote = "\"";
        this.reQuote = "";
        this.reEscape = Arrays.asList("\"");
        this.reEscapeChar = "\\";
        this.reExpression = "%s: /%s/";
        this.cidrExpression = "%s: \"%s\"";
        this.fieldNullExpression = "%s: null";
        this.unboundValueStrExpression = "%s: \"%s\"";
        this.unboundValueNumExpression = "%s: %s";
        this.unboundWildcardExpression = "%s: %s";
        this.unboundReExpression = "%s: /%s/";
        this.compareOpExpression = "\"%s\" \"%s\" %s";
        this.valExpCount = 0;
        this.aggQuery = "\"aggs\":{\"%s\":{\"terms\":{\"field\":\"%s\"},\"aggs\":{\"%s\":{\"%s\":{\"field\":\"%s\"}}}}}";
        this.aggCountQuery = "\"aggs\":{\"%s\":{\"terms\":{\"field\":\"%s\"}}}";
        this.bucketTriggerQuery = "{\"buckets_path\":{\"%s\":\"%s\"},\"parent_bucket_path\":\"%s\",\"script\":{\"source\":\"params.%s %s %s\",\"lang\":\"painless\"}}";
        this.bucketTriggerScript = "params.%s %s %s";
    }

    @Override
    public Object convertConditionAsInExpression(Either<ConditionAND, ConditionOR> condition) {
        if (condition.isLeft()) {
            return this.convertConditionAnd(condition.getLeft());
        }
        return this.convertConditionOr(condition.get());
    }

    @Override
    public Object convertConditionAnd(ConditionAND condition) {
        try {
            StringBuilder queryBuilder = new StringBuilder();
            StringBuilder joiner = new StringBuilder();
            if (this.tokenSeparator.equals(this.andToken)) {
                joiner.append(this.andToken);
            } else {
                joiner.append(this.tokenSeparator).append(this.andToken).append(this.tokenSeparator);
            }

            boolean first = true;
            for (Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg: condition.getArgs()) {
                Object converted = null;
                if (arg.isLeft()) {
                    if (arg.getLeft().isLeft()) {
                        ConditionType argType = arg.getLeft().getLeft().getClass().equals(ConditionAND.class)? new ConditionType(Either.left(AnyOneOf.leftVal((ConditionAND) arg.getLeft().getLeft()))):
                                (arg.getLeft().getLeft().getClass().equals(ConditionOR.class)? new ConditionType(Either.left(AnyOneOf.middleVal((ConditionOR) arg.getLeft().getLeft()))):
                                        new ConditionType(Either.left(AnyOneOf.rightVal((ConditionNOT) arg.getLeft().getLeft()))));
                        converted = this.convertConditionGroup(argType);
                    } else if (arg.getLeft().isMiddle()) {
                        converted = this.convertConditionGroup(new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                    } else if (arg.getLeft().isRight()) {
                        converted = this.convertConditionGroup(new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
                    }

                    if (converted != null) {
                        if (!first) {
                            queryBuilder.append(joiner).append(converted);
                        } else {
                            queryBuilder.append(converted);
                            first = false;
                        }

                    }
                }
            }
            return queryBuilder.toString();
        } catch (Exception ex) {
            throw new NotImplementedException("Operator 'and' not supported by the backend");
        }
    }

    @Override
    public Object convertConditionOr(ConditionOR condition) {
        try {
            StringBuilder queryBuilder = new StringBuilder();
            StringBuilder joiner = new StringBuilder();
            if (this.tokenSeparator.equals(this.orToken)) {
                joiner.append(this.orToken);
            } else {
                joiner.append(this.tokenSeparator).append(this.orToken).append(this.tokenSeparator);
            }

            boolean first = true;
            for (Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg: condition.getArgs()) {
                Object converted = null;
                if (arg.isLeft()) {
                    if (arg.getLeft().isLeft()) {
                        ConditionType argType = arg.getLeft().getLeft().getClass().equals(ConditionAND.class)? new ConditionType(Either.left(AnyOneOf.leftVal((ConditionAND) arg.getLeft().getLeft()))):
                                (arg.getLeft().getLeft().getClass().equals(ConditionOR.class)? new ConditionType(Either.left(AnyOneOf.middleVal((ConditionOR) arg.getLeft().getLeft()))):
                                        new ConditionType(Either.left(AnyOneOf.rightVal((ConditionNOT) arg.getLeft().getLeft()))));
                        converted = this.convertConditionGroup(argType);
                    } else if (arg.getLeft().isMiddle()) {
                        converted = this.convertConditionGroup(new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                    } else if (arg.getLeft().isRight()) {
                        converted = this.convertConditionGroup(new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
                    }

                    if (converted != null) {
                        if (!first) {
                            queryBuilder.append(joiner).append(converted);
                        } else {
                            queryBuilder.append(converted);
                            first = false;
                        }

                    }
                }
            }
            return queryBuilder.toString();
        } catch (Exception ex) {
            throw new NotImplementedException("Operator 'and' not supported by the backend");
        }
    }

    @Override
    public Object convertConditionNot(ConditionNOT condition) {
        Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg = condition.getArgs().get(0);
        try {
            if (arg.isLeft()) {
                if (arg.getLeft().isLeft()) {
                    ConditionType argType = arg.getLeft().getLeft().getClass().equals(ConditionAND.class) ? new ConditionType(Either.left(AnyOneOf.leftVal((ConditionAND) arg.getLeft().getLeft()))) :
                            (arg.getLeft().getLeft().getClass().equals(ConditionOR.class) ? new ConditionType(Either.left(AnyOneOf.middleVal((ConditionOR) arg.getLeft().getLeft()))) :
                                    new ConditionType(Either.left(AnyOneOf.rightVal((ConditionNOT) arg.getLeft().getLeft()))));
                    return String.format(Locale.getDefault(), groupExpression, this.notToken + this.tokenSeparator + this.convertConditionGroup(argType));
                } else if (arg.getLeft().isMiddle()) {
                    ConditionType argType = new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle())));
                    return String.format(Locale.getDefault(), groupExpression, this.notToken + this.tokenSeparator + this.convertCondition(argType).toString());
                } else {
                    ConditionType argType = new ConditionType(Either.right(Either.right(arg.getLeft().get())));
                    return String.format(Locale.getDefault(), groupExpression, this.notToken + this.tokenSeparator + this.convertCondition(argType).toString());
                }
            }
        } catch (Exception ex) {
            throw new NotImplementedException("Operator 'not' not supported by the backend");
        }
        return null;
    }

    @Override
    public Object convertConditionFieldEqValStr(ConditionFieldEqualsValueExpression condition) throws SigmaValueError {
        SigmaString value = (SigmaString) condition.getValue();
        boolean containsWildcard = value.containsWildcard();
        String expr = "%s" + this.eqToken + " " + (containsWildcard? this.reQuote: this.strQuote) + "%s" + (containsWildcard? this.reQuote: this.strQuote);

        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        return String.format(Locale.getDefault(), expr, field, this.convertValueStr(value));
    }

    @Override
    public Object convertConditionFieldEqValNum(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());

        SigmaNumber number = (SigmaNumber) condition.getValue();
        ruleQueryFields.put(field, number.getNumOpt().isLeft()? Collections.singletonMap("type", "integer"): Collections.singletonMap("type", "float"));

        return field + this.eqToken + " " + condition.getValue();
    }

    @Override
    public Object convertConditionFieldEqValBool(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Collections.singletonMap("type", "boolean"));

        return field + this.eqToken + " " + ((SigmaBool) condition.getValue()).isaBoolean();
    }

    public Object convertConditionFieldEqValNull(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        return String.format(Locale.getDefault(), this.fieldNullExpression, field);
    }

    @Override
    public Object convertConditionFieldEqValRe(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        return String.format(Locale.getDefault(), this.reExpression, field, convertValueRe((SigmaRegularExpression) condition.getValue()));
    }

    @Override
    public Object convertConditionFieldEqValCidr(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        return String.format(Locale.getDefault(), this.cidrExpression, field, convertValueCidr((SigmaCIDRExpression) condition.getValue()));
    }

    @Override
    public Object convertConditionFieldEqValOpVal(ConditionFieldEqualsValueExpression condition) {
        return String.format(Locale.getDefault(), this.compareOpExpression, this.getMappedField(condition.getField()),
                compareOperators.get(((SigmaCompareExpression) condition.getValue()).getOp()), ((SigmaCompareExpression) condition.getValue()).getNumber().toString());
    }

// TODO: below methods will be supported when Sigma Expand Modifier is supported.
//
/*    @Override
    public Object convertConditionFieldEqValNull(ConditionFieldEqualsValueExpression condition) {
        return null;
    }

    @Override
    public Object convertConditionFieldEqValQueryExpr(ConditionFieldEqualsValueExpression condition) {
        return null;
    }*/

    @Override
    public Object convertConditionValStr(ConditionValueExpression condition) throws SigmaValueError {
        SigmaString value = (SigmaString) condition.getValue();

        String field = getFinalValueField();
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        boolean containsWildcard = value.containsWildcard();
        return String.format(Locale.getDefault(), (containsWildcard? this.unboundWildcardExpression: this.unboundValueStrExpression), field, this.convertValueStr((SigmaString) condition.getValue()));
    }

    @Override
    public Object convertConditionValNum(ConditionValueExpression condition) {
        String field = getFinalValueField();

        SigmaNumber number = (SigmaNumber) condition.getValue();
        ruleQueryFields.put(field, number.getNumOpt().isLeft()? Collections.singletonMap("type", "integer"): Collections.singletonMap("type", "float"));

        return String.format(Locale.getDefault(), this.unboundValueNumExpression, field, condition.getValue().toString());
    }

    @Override
    public Object convertConditionValRe(ConditionValueExpression condition) {
        String field = getFinalValueField();
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        return String.format(Locale.getDefault(), this.unboundReExpression, field, convertValueRe((SigmaRegularExpression) condition.getValue()));
    }

// TODO: below methods will be supported when Sigma Expand Modifier is supported.
//
/*    @Override
    public Object convertConditionValQueryExpr(ConditionValueExpression condition) {
        return null;
    }*/

    @Override
    public Object convertAggregation(AggregationItem aggregation) throws SigmaConditionError {
        String fmtAggQuery;
        TermsAggregationBuilder aggBuilder = new TermsAggregationBuilder("result_agg");
        String fmtBucketTriggerQuery;
        BucketLevelTrigger bucketLevelTrigger;
        if (aggregation.getAggFunction().equals("count")) {
            if (aggregation.getAggField().equals("*") && aggregation.getGroupByField() == null) {
                fmtAggQuery = String.format(Locale.getDefault(), aggCountQuery, "result_agg", "_index");
                aggBuilder.field("_index");
            } else {
                fmtAggQuery = String.format(Locale.getDefault(), aggCountQuery, "result_agg", aggregation.getGroupByField());
                aggBuilder.field(aggregation.getGroupByField());
            }
            fmtBucketTriggerQuery = String.format(Locale.getDefault(), bucketTriggerQuery, "_cnt", "_cnt", "result_agg", "_cnt", aggregation.getCompOperator(), aggregation.getThreshold());

            String id = UUIDs.base64UUID();
            BucketSelectorExtAggregationBuilder bucketSelectorExtAggregationBuilder = new BucketSelectorExtAggregationBuilder(id, Map.of("_cnt", "_cnt"),
                    new Script(String.format(Locale.getDefault(), bucketTriggerScript, "_cnt", aggregation.getCompOperator(), aggregation.getThreshold())), "result_agg", null);
            bucketLevelTrigger = new BucketLevelTrigger(id, "sigma_rule_trigger", "1", bucketSelectorExtAggregationBuilder, List.of());
        } else {
            fmtAggQuery = String.format(Locale.getDefault(), aggQuery, "result_agg", aggregation.getGroupByField(), aggregation.getAggField(), aggregation.getAggFunction(), aggregation.getAggField());
            aggBuilder.field(aggregation.getGroupByField());

            switch (aggregation.getAggFunction()) {
                case "sum":
                    aggBuilder.subAggregation(new SumAggregationBuilder(aggregation.getAggField()).field(aggregation.getAggField()));
                    break;
                case "min":
                    aggBuilder.subAggregation(new MinAggregationBuilder(aggregation.getAggField()).field(aggregation.getAggField()));
                    break;
                case "max":
                    aggBuilder.subAggregation(new MaxAggregationBuilder(aggregation.getAggField()).field(aggregation.getAggField()));
                    break;
                case "avg":
                    aggBuilder.subAggregation(new AvgAggregationBuilder(aggregation.getAggField()).field(aggregation.getAggField()));
                    break;
                default:
                    throw new SigmaConditionError("Aggregation function is not supported");

            }
            fmtBucketTriggerQuery = String.format(Locale.getDefault(), bucketTriggerQuery, aggregation.getAggField(), aggregation.getAggField(), "result_agg", aggregation.getAggField(), aggregation.getCompOperator(), aggregation.getThreshold());

            String id = UUIDs.base64UUID();
            BucketSelectorExtAggregationBuilder bucketSelectorExtAggregationBuilder = new BucketSelectorExtAggregationBuilder(id, Map.of(aggregation.getAggField(), aggregation.getAggField()),
                    new Script(String.format(Locale.getDefault(), bucketTriggerScript, aggregation.getAggField(), aggregation.getCompOperator(), aggregation.getThreshold())), "result_agg", null);
            bucketLevelTrigger = new BucketLevelTrigger(id, "sigma_rule_trigger", "1", bucketSelectorExtAggregationBuilder, List.of());
        }
        AggregationQueries aggQueries = new AggregationQueries();
        aggQueries.setAggQuery(fmtAggQuery);
        aggQueries.setAggBuilder(aggBuilder);
        aggQueries.setBucketTriggerQuery(fmtBucketTriggerQuery);
        aggQueries.setBucketLevelTrigger(bucketLevelTrigger);
        return aggQueries;
    }

    private boolean comparePrecedence(ConditionType outer, ConditionType inner) {
        Class<?> outerClass = outer.getClazz();

        Class<?> innerClass = inner.getClazz();
        if ((inner.isEqualsValueExpression() && inner.getEqualsValueExpression().getValue() instanceof SigmaExpansion) ||
                (inner.isValueExpression() && inner.getValueExpression().getValue() instanceof SigmaExpansion)) {
            innerClass = ConditionOR.class;
        }

        int idxInner = precedence.indexOf(innerClass);
        return idxInner <= precedence.indexOf(outerClass);
    }

    private Object convertConditionGroup(ConditionType condition) throws SigmaValueError {
        return String.format(Locale.getDefault(), groupExpression, this.convertCondition(condition));
    }

    private Object convertValueStr(SigmaString s) throws SigmaValueError {
        return s.convert(escapeChar, wildcardMulti, wildcardSingle, addEscaped, addReserved, "");
    }

    private Object convertValueRe(SigmaRegularExpression re) {
        return re.escape(this.reEscape, this.reEscapeChar);
    }

    private Object convertValueCidr(SigmaCIDRExpression ip) {
        return ip.convert();
    }

    private String getMappedField(String field) {
        if (this.enableFieldMappings && this.fieldMappings.containsKey(field)) {
            return this.fieldMappings.get(field);
        }
        return field;
    }

    private String getFinalField(String field) {
        field = this.getMappedField(field);
        if (field.contains(".")) {
            field = field.replace(".", "_");
        }
        return field;
    }

    private String getFinalValueField() {
        String field = "_" + valExpCount;
        valExpCount++;
        return field;
    }

    public static class AggregationQueries implements Serializable {

        private String aggQuery;

        private TermsAggregationBuilder aggBuilder;

        private String bucketTriggerQuery;

        private BucketLevelTrigger bucketLevelTrigger;

        public void setAggQuery(String aggQuery) {
            this.aggQuery = aggQuery;
        }

        public void setAggBuilder(TermsAggregationBuilder aggBuilder) {
            this.aggBuilder = aggBuilder;
        }

        public String getAggQuery() {
            return aggQuery;
        }

        public TermsAggregationBuilder getAggBuilder() {
            return aggBuilder;
        }

        public void setBucketTriggerQuery(String bucketTriggerQuery) {
            this.bucketTriggerQuery = bucketTriggerQuery;
        }

        public void setBucketLevelTrigger(BucketLevelTrigger bucketLevelTrigger) {
            this.bucketLevelTrigger = bucketLevelTrigger;
        }

        public String getBucketTriggerQuery() {
            return bucketTriggerQuery;
        }
    }
}
