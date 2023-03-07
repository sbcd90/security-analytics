/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.InputStreamStreamInput;
import org.opensearch.common.io.stream.OutputStreamStreamOutput;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.commons.securityanalytics.action.CorrelateFindingsRequest;
import org.opensearch.commons.securityanalytics.action.CorrelateFindingsResponse;
import org.opensearch.commons.securityanalytics.action.SecurityAnalyticsActions;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.RangeQueryBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.correlation.index.query.CorrelationQueryBuilder;
import org.opensearch.securityanalytics.model.CorrelatedIndex;
import org.opensearch.securityanalytics.model.CorrelationField;
import org.opensearch.securityanalytics.model.CorrelationInfo;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.DetectorUtils;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class TransportCorrelateFindingAction extends HandledTransportAction<ActionRequest, CorrelateFindingsResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportCorrelateFindingAction.class);

    private final DetectorIndices detectorIndices;

    private final CorrelationIndices correlationIndices;

    private final ClusterService clusterService;

    private final Settings settings;

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    private volatile TimeValue indexTimeout;

    private final Map<String, Integer> logTypeToDim;

    private volatile long corrTimeWindow;

    private volatile long setupTimestamp;

    @Inject
    public TransportCorrelateFindingAction(TransportService transportService,
                                           Client client,
                                           NamedXContentRegistry xContentRegistry,
                                           DetectorIndices detectorIndices,
                                           CorrelationIndices correlationIndices,
                                           ClusterService clusterService,
                                           Settings settings,
                                           ActionFilters actionFilters) {
        super(SecurityAnalyticsActions.CORRELATE_FINDING_ACTION_NAME, transportService, actionFilters, CorrelateFindingsRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.detectorIndices = detectorIndices;
        this.correlationIndices = correlationIndices;
        this.clusterService = clusterService;
        this.settings = settings;
        this.threadPool = this.detectorIndices.getThreadPool();

        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
        this.corrTimeWindow = SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW.get(this.settings).getMillis();
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.INDEX_TIMEOUT, it -> indexTimeout = it);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW, it -> corrTimeWindow = it.getMillis());
        this.setupTimestamp = System.currentTimeMillis();

        this.logTypeToDim = new HashMap<>();
        this.logTypeToDim.put("others_application", 0);
        this.logTypeToDim.put("others_apt", 1);
        this.logTypeToDim.put("others_cloud", 2);
        this.logTypeToDim.put("others_compliance", 4);
        this.logTypeToDim.put("linux", 5);
        this.logTypeToDim.put("others_macos", 6);
        this.logTypeToDim.put("network", 7);
        this.logTypeToDim.put("others_proxy", 8);
        this.logTypeToDim.put("others_web", 9);
        this.logTypeToDim.put("windows", 10);
        this.logTypeToDim.put("ad_ldap", 11);
        this.logTypeToDim.put("apache_access", 12);
        this.logTypeToDim.put("cloudtrail", 14);
        this.logTypeToDim.put("dns", 15);
        this.logTypeToDim.put("s3", 16);
        this.logTypeToDim.put("test_windows", 17);
    }

    @Override
    protected void doExecute(Task task, ActionRequest request, ActionListener<CorrelateFindingsResponse> actionListener) {
        try {
            CorrelateFindingsRequest transformedRequest = transformRequest(request);
            AsyncCorrelateFindingAction correlateFindingAction = new AsyncCorrelateFindingAction(task, transformedRequest, actionListener);
            correlateFindingAction.start();
        } catch (IOException e) {
            throw new SecurityAnalyticsException("Unknown exception occurred", RestStatus.INTERNAL_SERVER_ERROR, e);
        }

    }

    class AsyncCorrelateFindingAction {
        private final CorrelateFindingsRequest request;

        private final ActionListener<CorrelateFindingsResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final long thresholdTimestamp;
        private final Task task;

        AsyncCorrelateFindingAction(Task task, CorrelateFindingsRequest request, ActionListener<CorrelateFindingsResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.thresholdTimestamp = System.currentTimeMillis() - CorrelationIndices.FIXED_HISTORICAL_INTERVAL;

            this.response =new AtomicReference<>();
        }

        void start() {
            log.info("hit here1-" + corrTimeWindow);
            TransportCorrelateFindingAction.this.threadPool.getThreadContext().stashContext();
            String monitorId = request.getMonitorId();

            if (detectorIndices.detectorIndexExists()) {
                NestedQueryBuilder queryBuilder =
                        QueryBuilders.nestedQuery(
                                "detector",
                                QueryBuilders.matchQuery(
                                        DetectorUtils.DETECTOR_MONITOR_ID_PATH,
                                        monitorId
                                ),
                                ScoreMode.None
                        );

                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(queryBuilder);
                searchSourceBuilder.fetchSource(true);
                searchSourceBuilder.size(10000);
                SearchRequest searchRequest = new SearchRequest();
                searchRequest.indices(Detector.DETECTORS_INDEX);
                searchRequest.source(searchSourceBuilder);

                client.search(searchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.isTimedOut()) {
                            onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                        }

                        SearchHits hits = response.getHits();
                        assert hits.getTotalHits().value == 1;
                        try {
                            SearchHit hit = hits.getAt(0);

                            XContentParser xcp = XContentType.JSON.xContent().createParser(
                                    xContentRegistry,
                                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                            );
                            Detector detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
                            onSearchDetectorResponse(detector);
                        } catch (IOException e) {
                            onFailures(e);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } else {
                onFailures(new SecurityAnalyticsException(String.format(Locale.getDefault(), "Detector index %s doesnt exist", Detector.DETECTORS_INDEX), RestStatus.INTERNAL_SERVER_ERROR, new RuntimeException()));
            }
        }

        private void onSearchDetectorResponse(Detector detector) {
            String detectorType = detector.getDetectorType().toLowerCase(Locale.ROOT);
            List<String> indices = detector.getInputs().get(0).getIndices();
            List<CorrelatedIndex> correlatedIndices = detector.getInputs().get(0).getCorrelatedIndices();
            Finding finding = request.getFinding();

            if (indices == null || indices.size() == 0) {
                CorrelatedIndex correlatedIndex = correlatedIndices.get(0);
                String detectorIndex = correlatedIndex.getIndex();
                List<CorrelationInfo> correlationInfoList = correlatedIndex.getCorrelationInfos();

                List<String> relatedDocIds = finding.getCorrelatedDocIds();
                Map<String, DocSearchCriteria> docSearchCriteriaMap = new HashMap<>();
                List<ParentJoinCriteria> parentJoinCriteriaList = new ArrayList<>();

                for (CorrelationInfo correlationInfo: correlationInfoList) {
                    if (correlationInfo.getFields().size() > 0) {
                        // todo support multi-joins
                        CorrelationField field = correlationInfo.getFields().get(0);
                        Boolean isQuery = field.getQuery();
                        Map<String, Object> joinFields = field.getFields();

                        String joinKey = null;
                        Object joinValue = null;
                        String parentJoinKey = null;
                        Object parentJoinValue = null;
                        for (Map.Entry<String, Object> joinField: joinFields.entrySet()) {
                            if (joinField.getKey().startsWith(detectorType)) {
                                joinKey = isQuery ? joinField.getKey(): joinField.getKey().replace(detectorType + "-", "");
                                joinValue = joinField.getValue();
                            }
                            if (joinField.getKey().startsWith(correlationInfo.getCategory())) {
                                parentJoinKey = isQuery? joinField.getKey(): joinField.getKey().replace(correlationInfo.getCategory() + "-", "");
                                parentJoinValue = joinField.getValue();
                            }
                        }

                        docSearchCriteriaMap.put(correlationInfo.getCategory(),
                                new DocSearchCriteria(detectorIndex, joinKey, joinValue, relatedDocIds, correlationInfo.getIndex(), parentJoinKey, parentJoinValue, isQuery));
                    } else {
                        if (correlationInfo.getIndex() != null) {
                            docSearchCriteriaMap.put(correlationInfo.getCategory(),
                                    new DocSearchCriteria(detectorIndex, null, null, relatedDocIds, correlationInfo.getIndex(), null, null, false));
                        } else {
                            parentJoinCriteriaList.add(new ParentJoinCriteria(correlationInfo.getCategory(), null, null, null, false));
                        }
                    }
                }

                if (!docSearchCriteriaMap.isEmpty()) {
                    getValidDocuments(detectorType, docSearchCriteriaMap);
                } else {
                    getCorrelatedFindings(detectorType, parentJoinCriteriaList);
                }
            } else {
                initCorrelationIndex(detectorType, Map.of());
            }
        }

        private void getValidDocuments(String detectorType, Map<String, DocSearchCriteria> docSearchCriteriaMap) {
            MultiSearchRequest mSearchRequest = new MultiSearchRequest();
            List<ParentJoinCriteria> parentJoinCriteriaList = new ArrayList<>();
            List<ParentJoinCriteria> parentCriteriaWithoutJoin = new ArrayList<>();

            for (Map.Entry<String, DocSearchCriteria> docSearchCriteria : docSearchCriteriaMap.entrySet()) {
                if (docSearchCriteria.getValue().joinKey != null) {
                    BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                            .filter(QueryBuilders.termsQuery("_id", docSearchCriteria.getValue().relatedDocIds));

                    if (docSearchCriteria.getValue().isQuery) {
                        queryBuilder = queryBuilder.must(QueryBuilders.queryStringQuery(docSearchCriteria.getValue().joinValue.toString()));
                    } else {
                        queryBuilder = queryBuilder.must(QueryBuilders.matchQuery(docSearchCriteria.getValue().joinKey, docSearchCriteria.getValue().joinValue));
                    }

                    SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                    searchSourceBuilder.query(queryBuilder);
                    searchSourceBuilder.fetchSource(false);
                    searchSourceBuilder.size(10000);
                    SearchRequest searchRequest = new SearchRequest();
                    searchRequest.indices(docSearchCriteria.getValue().index);
                    searchRequest.source(searchSourceBuilder);
                    parentJoinCriteriaList.add(new ParentJoinCriteria(docSearchCriteria.getKey(),
                            docSearchCriteria.getValue().parentIndex, docSearchCriteria.getValue().parentJoinKey, docSearchCriteria.getValue().parentJoinValue, docSearchCriteria.getValue().isQuery));
                    mSearchRequest.add(searchRequest);
                } else {
                    parentCriteriaWithoutJoin.add(new ParentJoinCriteria(docSearchCriteria.getKey(),
                            docSearchCriteria.getValue().parentIndex, null, null, docSearchCriteria.getValue().isQuery));
                }
            }

            if (!mSearchRequest.requests().isEmpty()) {
                client.multiSearch(mSearchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(MultiSearchResponse items) {
                        MultiSearchResponse.Item[] responses = items.getResponses();
                        List<ParentJoinCriteria> validParentJoinCriteriaList = new ArrayList<>();

                        int idx = 0;
                        for (MultiSearchResponse.Item response : responses) {
                            if (response.isFailure()) {
                                log.info(response.getFailureMessage());
                                continue;
                            }

                            if (response.getResponse().getHits().getTotalHits().value > 0L) {
                                validParentJoinCriteriaList.add(parentJoinCriteriaList.get(idx));
                            }
                            ++idx;
                        }
                        searchFindingsByTimestamp(detectorType, validParentJoinCriteriaList);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } else {
                searchFindingsByTimestamp(detectorType, parentCriteriaWithoutJoin);
            }
        }

        private void searchFindingsByTimestamp(String detectorType, List<ParentJoinCriteria> parentFindingJoinCriteriaList) {
            long findingTimestamp = request.getFinding().getTimestamp().toEpochMilli();
            MultiSearchRequest mSearchRequest = new MultiSearchRequest();

            for (ParentJoinCriteria parentJoinCriteria: parentFindingJoinCriteriaList) {
                log.info("timestamp range during getCorrelatedFindings-" + (findingTimestamp - corrTimeWindow) + "-" + (findingTimestamp + corrTimeWindow));
                RangeQueryBuilder queryBuilder = QueryBuilders.rangeQuery("timestamp")
                        .gte(findingTimestamp - corrTimeWindow)
                        .lte(findingTimestamp + corrTimeWindow);

                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(queryBuilder);
                searchSourceBuilder.fetchSource(false);
                searchSourceBuilder.size(10000);
                searchSourceBuilder.fetchField("correlated_doc_ids");
                SearchRequest searchRequest = new SearchRequest();
                searchRequest.indices(DetectorMonitorConfig.getAllFindingsIndicesPattern(parentJoinCriteria.category));
                searchRequest.source(searchSourceBuilder);
                mSearchRequest.add(searchRequest);
            }

            if (!mSearchRequest.requests().isEmpty()) {
                client.multiSearch(mSearchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(MultiSearchResponse items) {
                        MultiSearchResponse.Item[] responses = items.getResponses();
                        Map<String, DocSearchCriteria> relatedDocsMap = new HashMap<>();

                        int idx = 0;
                        for (MultiSearchResponse.Item response : responses) {
                            if (response.isFailure()) {
                                log.info(response.getFailureMessage());
                                continue;
                            }

                            List<String> relatedDocIds = new ArrayList<>();
                            SearchHit[] hits = response.getResponse().getHits().getHits();
                            for (SearchHit hit : hits) {
                                relatedDocIds.addAll(hit.getFields().get("correlated_doc_ids").getValues().stream()
                                        .map(Object::toString).collect(Collectors.toList()));
                            }
                            relatedDocsMap.put(parentFindingJoinCriteriaList.get(idx).category,
                                    new DocSearchCriteria(
                                            parentFindingJoinCriteriaList.get(idx).index,
                                            parentFindingJoinCriteriaList.get(idx).parentJoinKey,
                                            parentFindingJoinCriteriaList.get(idx).parentJoinValue,
                                            relatedDocIds,
                                            null,
                                            null,
                                            null,
                                            parentFindingJoinCriteriaList.get(idx).isQuery));
                            ++idx;
                        }

                        for (Map.Entry<String, DocSearchCriteria> relatedDocs : relatedDocsMap.entrySet()) {
                            log.info(relatedDocs.getKey() + " " + relatedDocs.getValue().index);
                        }
                        searchDocsWithFilterKeys(detectorType, relatedDocsMap);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } else {
                getTimestampFeature(detectorType, null, request.getFinding());
            }
        }

        private void searchDocsWithFilterKeys(String detectorType, Map<String, DocSearchCriteria> relatedDocsMap) {
            MultiSearchRequest mSearchRequest = new MultiSearchRequest();
            List<String> categories = new ArrayList<>();

            for (Map.Entry<String, DocSearchCriteria> docSearchCriteria: relatedDocsMap.entrySet()) {
                BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                        .filter(QueryBuilders.termsQuery("_id", docSearchCriteria.getValue().relatedDocIds));

                if (docSearchCriteria.getValue().joinKey != null) {
                    if (docSearchCriteria.getValue().isQuery) {
                        queryBuilder = queryBuilder.must(QueryBuilders.queryStringQuery(docSearchCriteria.getValue().joinValue.toString()));
                    } else {
                        queryBuilder = queryBuilder.
                                must(QueryBuilders.matchQuery(docSearchCriteria.getValue().joinKey, docSearchCriteria.getValue().joinValue));
                    }
                }

                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(queryBuilder);
                searchSourceBuilder.fetchSource(false);
                searchSourceBuilder.size(10000);
                SearchRequest searchRequest = new SearchRequest();
                searchRequest.indices(docSearchCriteria.getValue().index);
                searchRequest.source(searchSourceBuilder);

                categories.add(docSearchCriteria.getKey());
                mSearchRequest.add(searchRequest);
            }

            if (!mSearchRequest.requests().isEmpty()) {
                client.multiSearch(mSearchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(MultiSearchResponse items) {
                        MultiSearchResponse.Item[] responses = items.getResponses();
                        Map<String, List<String>> filteredRelatedDocIds = new HashMap<>();

                        int idx = 0;
                        for (MultiSearchResponse.Item response : responses) {
                            if (response.isFailure()) {
                                log.info(response.getFailureMessage());
                                continue;
                            }

                            SearchHit[] hits = response.getResponse().getHits().getHits();
                            List<String> docIds = new ArrayList<>();

                            for (SearchHit hit : hits) {
                                docIds.add(hit.getId());
                            }
                            filteredRelatedDocIds.put(categories.get(idx), docIds);
                            ++idx;
                        }

                        for (Map.Entry<String, List<String>> filteredRelatedDocId: filteredRelatedDocIds.entrySet()) {
                            log.info(filteredRelatedDocId.getKey() + "-" + filteredRelatedDocId.getValue().size());
                        }
                        getCorrelatedFindings(detectorType, filteredRelatedDocIds);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } else {
                getTimestampFeature(detectorType, null, request.getFinding());
            }
        }

        private void getCorrelatedFindings(String detectorType, List<ParentJoinCriteria> parentJoinCriteriaList) {
            long findingTimestamp = request.getFinding().getTimestamp().toEpochMilli();
            MultiSearchRequest mSearchRequest = new MultiSearchRequest();
            List<String> categories = new ArrayList<>();

            for (ParentJoinCriteria parentJoinCriteria: parentJoinCriteriaList) {
                RangeQueryBuilder queryBuilder = QueryBuilders.rangeQuery("timestamp")
                        .gte(findingTimestamp - corrTimeWindow)
                        .lte(findingTimestamp + corrTimeWindow);

                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(queryBuilder);
                searchSourceBuilder.fetchSource(false);
                searchSourceBuilder.size(10000);
                SearchRequest searchRequest = new SearchRequest();
                searchRequest.indices(DetectorMonitorConfig.getAllFindingsIndicesPattern(parentJoinCriteria.category));
                searchRequest.source(searchSourceBuilder);

                categories.add(parentJoinCriteria.category);
                mSearchRequest.add(searchRequest);
            }

            if (!mSearchRequest.requests().isEmpty()) {
                client.multiSearch(mSearchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(MultiSearchResponse items) {
                        MultiSearchResponse.Item[] responses = items.getResponses();
                        Map<String, List<String>> correlatedFindings = new HashMap<>();

                        int idx = 0;
                        for (MultiSearchResponse.Item response : responses) {
                            if (response.isFailure()) {
                                log.info(response.getFailureMessage());
                                continue;
                            }

                            SearchHit[] hits = response.getResponse().getHits().getHits();
                            List<String> findings = new ArrayList<>();

                            for (SearchHit hit : hits) {
                                findings.add(hit.getId());
                            }

                            if (!findings.isEmpty()) {
                                correlatedFindings.put(categories.get(idx), findings);
                            }
                            ++idx;
                        }
                        initCorrelationIndex(detectorType, correlatedFindings);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } else {
                getTimestampFeature(detectorType, null, request.getFinding());
            }
        }

        private void getCorrelatedFindings(String detectorType, Map<String, List<String>> filteredRelatedDocIds) {
            long findingTimestamp = request.getFinding().getTimestamp().toEpochMilli();
            MultiSearchRequest mSearchRequest = new MultiSearchRequest();
            List<String> categories = new ArrayList<>();

            for (Map.Entry<String, List<String>> relatedDocIds: filteredRelatedDocIds.entrySet()) {
                log.info("timestamp range during getCorrelatedFindings-" + (findingTimestamp - corrTimeWindow) + "-" + (findingTimestamp + corrTimeWindow) + "-" + (relatedDocIds.getValue().size() > 0? relatedDocIds.getValue().get(0): null));
                BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                        .filter(QueryBuilders.rangeQuery("timestamp")
                                .gte(findingTimestamp - corrTimeWindow)
                                .lte(findingTimestamp + corrTimeWindow))
                        .must(QueryBuilders.termsQuery("correlated_doc_ids", relatedDocIds.getValue()));

                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(queryBuilder);
                searchSourceBuilder.fetchSource(false);
                searchSourceBuilder.size(10000);
                SearchRequest searchRequest = new SearchRequest();
                searchRequest.indices(DetectorMonitorConfig.getAllFindingsIndicesPattern(relatedDocIds.getKey()));
                searchRequest.source(searchSourceBuilder);

                categories.add(relatedDocIds.getKey());
                mSearchRequest.add(searchRequest);
            }

            if (!mSearchRequest.requests().isEmpty()) {
                client.multiSearch(mSearchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(MultiSearchResponse items) {
                        MultiSearchResponse.Item[] responses = items.getResponses();
                        Map<String, List<String>> correlatedFindings = new HashMap<>();

                        int idx = 0;
                        for (MultiSearchResponse.Item response : responses) {
                            if (response.isFailure()) {
                                log.info(response.getFailureMessage());
                                continue;
                            }

                            SearchHit[] hits = response.getResponse().getHits().getHits();
                            List<String> findings = new ArrayList<>();

                            for (SearchHit hit : hits) {
                                findings.add(hit.getId());
                            }

                            if (!findings.isEmpty()) {
                                correlatedFindings.put(categories.get(idx), findings);
                            }
                            ++idx;
                        }

                        log.info("correlated finding");
                        for (Map.Entry<String, List<String>> correlatedFinding: correlatedFindings.entrySet()) {
                            log.info(correlatedFinding.getKey() + "-" + correlatedFinding.getValue().size());
                        }
                        initCorrelationIndex(detectorType, correlatedFindings);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } else {
                getTimestampFeature(detectorType, null, request.getFinding());
            }
        }

        public void insertCorrelatedFindings(String detectorType, Finding finding, String logType, List<String> correlatedFindings, float timestampFeature) {
            long findingTimestamp = finding.getTimestamp().toEpochMilli();
            MatchQueryBuilder queryBuilder = QueryBuilders.matchQuery(
                    "root", true
            );
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(queryBuilder);
            searchSourceBuilder.fetchSource(true);
            searchSourceBuilder.size(1);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
            searchRequest.source(searchSourceBuilder);

            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    if (response.isTimedOut()) {
                        onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                    }

                    Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
                    long counter = Long.parseLong(hitSource.get("counter").toString());

                    MultiSearchRequest mSearchRequest = new MultiSearchRequest();

                    for (String correlatedFinding: correlatedFindings) {
                        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                                .must(QueryBuilders.matchQuery(
                                        "finding1", correlatedFinding
                                )).must(QueryBuilders.matchQuery(
                                        "finding2", ""
                                )).must(QueryBuilders.matchQuery(
                                        "counter", counter
                                ));
                        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                        searchSourceBuilder.query(queryBuilder);
                        searchSourceBuilder.fetchSource(true);
                        searchSourceBuilder.size(10000);
                        SearchRequest searchRequest = new SearchRequest();
                        searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
                        searchRequest.source(searchSourceBuilder);

                        mSearchRequest.add(searchRequest);
                    }

                    client.multiSearch(mSearchRequest, new ActionListener<>() {
                        @Override
                        public void onResponse(MultiSearchResponse items) {
                            MultiSearchResponse.Item[] responses = items.getResponses();
                            BulkRequest bulkRequest = new BulkRequest();
                            bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                            long prevCounter = -1L;
                            long totalNeighbors = 0L;
                            for (MultiSearchResponse.Item response: responses) {
                                if (response.isFailure()) {
                                    log.info(response.getFailureMessage());
                                    continue;
                                }

                                long totalHits = response.getResponse().getHits().getTotalHits().value;
                                totalNeighbors += totalHits;

                                for (int idx = 0; idx < totalHits; ++idx) {
                                    SearchHit hit = response.getResponse().getHits().getHits()[idx];
                                    Map<String, Object> hitSource = hit.getSourceAsMap();
                                    long counter = Long.parseLong(hitSource.get("counter").toString());
                                    String correlatedFinding = hitSource.get("finding1").toString();

                                    try {
                                        float[] corrVector = new float[101];
                                        if (counter != prevCounter) {
                                            for (int i = 0; i < 100; ++i) {
                                                corrVector[i] = ((float) counter) - 50.0f;
                                            }
                                            corrVector[logTypeToDim.get(detectorType)] = (float) counter;
                                            corrVector[100] = timestampFeature;

                                            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                            builder.field("root", false);
                                            builder.field("counter", counter);
                                            builder.field("finding1", finding.getId());
                                            builder.field("finding2", "");
                                            builder.field("logType", logTypeToDim.get(detectorType).toString());
                                            builder.field("timestamp", findingTimestamp);
                                            builder.field("corr_vector", corrVector);
                                            builder.field("recordType", "finding");
                                            builder.field("scoreTimestamp", 0L);
                                            builder.endObject();

                                            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                    .source(builder)
                                                    .timeout(indexTimeout);
                                            bulkRequest.add(indexRequest);
                                        }

                                        corrVector = new float[101];
                                        for (int i = 0; i < 100; ++i) {
                                            corrVector[i] = ((float) counter) - 50.0f;
                                        }
                                        corrVector[logTypeToDim.get(detectorType)] = (2.0f * ((float) counter) - 50.0f) / 2.0f;
                                        corrVector[logTypeToDim.get(logType)] = (2.0f * ((float) counter) - 50.0f) / 2.0f;
                                        corrVector[100] = timestampFeature;

                                        XContentBuilder corrBuilder = XContentFactory.jsonBuilder().startObject();
                                        corrBuilder.field("root", false);
                                        corrBuilder.field("counter", (long) ((2.0f * ((float) counter) - 50.0f) / 2.0f));
                                        corrBuilder.field("finding1", finding.getId());
                                        corrBuilder.field("finding2", correlatedFinding);
                                        corrBuilder.field("logType", String.format(Locale.ROOT, "%s-%s", detectorType, logType));
                                        corrBuilder.field("timestamp", findingTimestamp);
                                        corrBuilder.field("corr_vector", corrVector);
                                        corrBuilder.field("recordType", "finding-finding");
                                        corrBuilder.field("scoreTimestamp", 0L);
                                        corrBuilder.endObject();

                                        IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                .source(corrBuilder)
                                                .timeout(indexTimeout);
                                        bulkRequest.add(indexRequest);
                                    } catch (IOException ex) {
                                        onFailures(ex);
                                    }
                                    prevCounter = counter;
                                }
                            }

                            if (totalNeighbors > 0L) {
                                client.bulk(bulkRequest, new ActionListener<>() {
                                    @Override
                                    public void onResponse(BulkResponse response) {
                                        if (response.hasFailures()) {
                                            onFailures(new OpenSearchStatusException("Correlation of finding failed", RestStatus.INTERNAL_SERVER_ERROR));
                                        }
                                        onOperation();
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        onFailures(e);
                                    }
                                });
                            } else {
                                insertOrphanFindings(detectorType, finding, timestampFeature);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        public void insertOrphanFindings(String detectorType, Finding finding, float timestampFeature) {
            long findingTimestamp = finding.getTimestamp().toEpochMilli();
            MatchQueryBuilder queryBuilder = QueryBuilders.matchQuery(
                    "root", true
            );
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(queryBuilder);
            searchSourceBuilder.fetchSource(true);
            searchSourceBuilder.size(1);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
            searchRequest.source(searchSourceBuilder);

            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    if (response.isTimedOut()) {
                        onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                    }

                    try {
                        Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
                        String id = response.getHits().getHits()[0].getId();
                        long counter = Long.parseLong(hitSource.get("counter").toString());
                        long timestamp = Long.parseLong(hitSource.get("timestamp").toString());
                        if (counter == 0L) {
                            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                            builder.field("root", true);
                            builder.field("counter", 50L);
                            builder.field("finding1", "");
                            builder.field("finding2", "");
                            builder.field("logType", "");
                            builder.field("timestamp", findingTimestamp);
                            builder.field("scoreTimestamp", 0L);
                            builder.endObject();

                            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                    .id(id)
                                    .source(builder)
                                    .timeout(indexTimeout)
                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                            client.index(indexRequest, new ActionListener<>() {
                                @Override
                                public void onResponse(IndexResponse response) {
                                    if (response.status().equals(RestStatus.OK)) {
                                        try {
                                            float[] corrVector = new float[101];
                                            corrVector[logTypeToDim.get(detectorType)] = 50.0f;
                                            corrVector[100] = timestampFeature;

                                            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                            builder.field("root", false);
                                            builder.field("counter", 50L);
                                            builder.field("finding1", finding.getId());
                                            builder.field("finding2", "");
                                            builder.field("logType", logTypeToDim.get(detectorType).toString());
                                            builder.field("timestamp", findingTimestamp);
                                            builder.field("corr_vector", corrVector);
                                            builder.field("recordType", "finding");
                                            builder.field("scoreTimestamp", 0L);
                                            builder.endObject();

                                            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                    .source(builder)
                                                    .timeout(indexTimeout)
                                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                            client.index(indexRequest, new ActionListener<>() {
                                                @Override
                                                public void onResponse(IndexResponse response) {
                                                    if (response.status().equals(RestStatus.CREATED)) {
                                                        onOperation();
                                                    } else {
                                                        onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    onFailures(e);
                                                }
                                            });
                                        } catch (IOException ex) {
                                            onFailures(ex);
                                        }
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            });
                        } else {
                            if (findingTimestamp - timestamp > corrTimeWindow) {
                                XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                builder.field("root", true);
                                builder.field("counter", 50L);
                                builder.field("finding1", "");
                                builder.field("finding2", "");
                                builder.field("logType", "");
                                builder.field("timestamp", findingTimestamp);
                                builder.field("scoreTimestamp", 0L);
                                builder.endObject();

                                IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                        .id(id)
                                        .source(builder)
                                        .timeout(indexTimeout)
                                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                client.index(indexRequest, new ActionListener<>() {
                                    @Override
                                    public void onResponse(IndexResponse response) {
                                        if (response.status().equals(RestStatus.OK)) {
                                            onOperation();
                                            try {
                                                float[] corrVector = new float[101];
                                                corrVector[logTypeToDim.get(detectorType)] = 50.0f;
                                                corrVector[100] = timestampFeature;

                                                XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                                builder.field("root", false);
                                                builder.field("counter", 50L);
                                                builder.field("finding1", finding.getId());
                                                builder.field("finding2", "");
                                                builder.field("logType", logTypeToDim.get(detectorType).toString());
                                                builder.field("timestamp", findingTimestamp);
                                                builder.field("corr_vector", corrVector);
                                                builder.field("recordType", "finding");
                                                builder.field("scoreTimestamp", 0L);
                                                builder.endObject();

                                                IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                        .source(builder)
                                                        .timeout(indexTimeout)
                                                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                                client.index(indexRequest, new ActionListener<>() {
                                                    @Override
                                                    public void onResponse(IndexResponse response) {
                                                        if (response.status().equals(RestStatus.CREATED)) {
                                                            onOperation();
                                                        } else {
                                                            onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                                        }
                                                    }

                                                    @Override
                                                    public void onFailure(Exception e) {
                                                        onFailures(e);
                                                    }
                                                });
                                            } catch (IOException ex) {
                                                onFailures(ex);
                                            }
                                        }
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        onFailures(e);
                                    }
                                });
                            } else {
                                float[] query = new float[101];
                                for (int i = 0; i < 100; ++i) {
                                    query[i] = (2.0f * ((float) counter) - 50.0f) / 2.0f;
                                }
                                query[100] = timestampFeature;

                                CorrelationQueryBuilder correlationQueryBuilder = new CorrelationQueryBuilder("corr_vector", query, 100, QueryBuilders.boolQuery()
                                        .mustNot(QueryBuilders.matchQuery(
                                                "finding1", ""
                                        )).mustNot(QueryBuilders.matchQuery(
                                                "finding2", ""
                                        )).filter(QueryBuilders.rangeQuery("timestamp")
                                                .gte(findingTimestamp - corrTimeWindow)
                                                .lte(findingTimestamp + corrTimeWindow)));
                                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                                searchSourceBuilder.query(correlationQueryBuilder);
                                searchSourceBuilder.fetchSource(true);
                                searchSourceBuilder.size(1);
                                SearchRequest searchRequest = new SearchRequest();
                                searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
                                searchRequest.source(searchSourceBuilder);

                                client.search(searchRequest, new ActionListener<>() {
                                    @Override
                                    public void onResponse(SearchResponse response) {
                                        if (response.isTimedOut()) {
                                            onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                                        }

                                        long totalHits = response.getHits().getTotalHits().value;
                                        SearchHit hit = totalHits > 0? response.getHits().getHits()[0]: null;
                                        long existCounter = 0L;

                                        if (hit != null) {
                                            Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
                                            existCounter = Long.parseLong(hitSource.get("counter").toString());
                                        }

                                        if (totalHits == 0L || existCounter != ((long) (2.0f * ((float) counter) - 50.0f) / 2.0f)) {
                                            try {
                                                float[] corrVector = new float[101];
                                                for (int i = 0; i < 100; ++i) {
                                                    corrVector[i] = ((float) counter) - 50.0f;
                                                }
                                                corrVector[logTypeToDim.get(detectorType)] = (float) counter;
                                                corrVector[100] = timestampFeature;

                                                XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                                builder.field("root", false);
                                                builder.field("counter", counter);
                                                builder.field("finding1", finding.getId());
                                                builder.field("finding2", "");
                                                builder.field("logType", logTypeToDim.get(detectorType).toString());
                                                builder.field("timestamp", findingTimestamp);
                                                builder.field("corr_vector", corrVector);
                                                builder.field("recordType", "finding");
                                                builder.field("scoreTimestamp", 0L);
                                                builder.endObject();

                                                IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                        .source(builder)
                                                        .timeout(indexTimeout)
                                                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                                client.index(indexRequest, new ActionListener<>() {
                                                    @Override
                                                    public void onResponse(IndexResponse response) {
                                                        if (response.status().equals(RestStatus.CREATED)) {
                                                            onOperation();
                                                        } else {
                                                            onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                                        }
                                                    }

                                                    @Override
                                                    public void onFailure(Exception e) {
                                                        onFailures(e);
                                                    }
                                                });
                                            } catch (IOException ex) {
                                                onFailures(ex);
                                            }
                                        } else {
                                            try {
                                                XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                                builder.field("root", true);
                                                builder.field("counter", counter + 50L);
                                                builder.field("finding1", "");
                                                builder.field("finding2", "");
                                                builder.field("logType", "");
                                                builder.field("timestamp", findingTimestamp);
                                                builder.field("scoreTimestamp", 0L);
                                                builder.endObject();

                                                IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                        .id(id)
                                                        .source(builder)
                                                        .timeout(indexTimeout)
                                                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                                client.index(indexRequest, new ActionListener<>() {
                                                    @Override
                                                    public void onResponse(IndexResponse response) {
                                                        if (response.status().equals(RestStatus.OK)) {
                                                            try {
                                                                float[] corrVector = new float[101];
                                                                for (int i = 0; i < 100; ++i) {
                                                                    corrVector[i] = (float) counter;
                                                                }
                                                                corrVector[logTypeToDim.get(detectorType)] = counter + 50.0f;
                                                                corrVector[100] = timestampFeature;

                                                                XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                                                builder.field("root", false);
                                                                builder.field("counter", counter + 50L);
                                                                builder.field("finding1", finding.getId());
                                                                builder.field("finding2", "");
                                                                builder.field("logType", logTypeToDim.get(detectorType).toString());
                                                                builder.field("timestamp", findingTimestamp);
                                                                builder.field("corr_vector", corrVector);
                                                                builder.field("recordType", "finding");
                                                                builder.field("scoreTimestamp", 0L);
                                                                builder.endObject();

                                                                IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                                        .source(builder)
                                                                        .timeout(indexTimeout)
                                                                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                                                client.index(indexRequest, new ActionListener<>() {
                                                                    @Override
                                                                    public void onResponse(IndexResponse response) {
                                                                        if (response.status().equals(RestStatus.CREATED)) {
                                                                            onOperation();
                                                                        } else {
                                                                            onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                                                        }
                                                                    }

                                                                    @Override
                                                                    public void onFailure(Exception e) {
                                                                        onFailures(e);
                                                                    }
                                                                });
                                                            } catch (IOException ex) {
                                                                onFailures(ex);
                                                            }
                                                        }
                                                    }

                                                    @Override
                                                    public void onFailure(Exception e) {
                                                        onFailures(e);
                                                    }
                                                });
                                            } catch (IOException ex) {
                                                onFailures(ex);
                                            }
                                        }
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        onFailures(e);
                                    }
                                });
                            }
                        }
                    } catch (IOException ex) {
                        onFailures(ex);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        private void initCorrelationIndex(String detectorType, Map<String, List<String>> correlatedFindings) {
            try {
                if (!correlationIndices.correlationIndexExists()) {
                    correlationIndices.initCorrelationIndex(new ActionListener<>() {
                        @Override
                        public void onResponse(CreateIndexResponse response) {
                            if (response.isAcknowledged()) {
                                IndexUtils.correlationIndexUpdated();
                                setupCorrelationIndex(detectorType, correlatedFindings);
                            } else {
                                onFailures(new OpenSearchStatusException("Failed to create correlation Index", RestStatus.INTERNAL_SERVER_ERROR));
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
                } else if (!IndexUtils.correlationIndexUpdated) {
                    IndexUtils.updateIndexMapping(
                            CorrelationIndices.CORRELATION_INDEX,
                            CorrelationIndices.correlationMappings(), clusterService.state(), client.admin().indices(),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse response) {
                                    if (response.isAcknowledged()) {
                                        IndexUtils.correlationIndexUpdated();
                                        getTimestampFeature(detectorType, correlatedFindings, null);
                                    } else {
                                        onFailures(new OpenSearchStatusException("Failed to create correlation Index", RestStatus.INTERNAL_SERVER_ERROR));
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            }
                    );
                } else {
                    getTimestampFeature(detectorType, correlatedFindings, null);
                }
            } catch (IOException ex) {
                onFailures(ex);
            }
        }

        private void setupCorrelationIndex(String detectorType, Map<String, List<String>> correlatedFindings) {
            try {
                long currentTimestamp = System.currentTimeMillis();
                XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                builder.field("root", true);
                builder.field("counter", 0L);
                builder.field("finding1", "");
                builder.field("finding2", "");
                builder.field("logType", "");
                builder.field("timestamp", currentTimestamp);
                builder.field("scoreTimestamp", 0L);
                builder.endObject();

                IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                        .source(builder)
                        .timeout(indexTimeout);

                XContentBuilder scoreBuilder = XContentFactory.jsonBuilder().startObject();
                scoreBuilder.field("scoreTimestamp", setupTimestamp);
                scoreBuilder.field("root", false);
                scoreBuilder.endObject();

                IndexRequest scoreIndexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                        .source(scoreBuilder)
                        .timeout(indexTimeout);

                BulkRequest bulkRequest = new BulkRequest();
                bulkRequest.add(indexRequest);
                bulkRequest.add(scoreIndexRequest);
                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);


                client.bulk(bulkRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(BulkResponse response) {
                        if (response.hasFailures()) {
                            onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                        }
                        getTimestampFeature(detectorType, correlatedFindings, null);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } catch (IOException ex) {
                onFailures(ex);
            }
        }

        private void getTimestampFeature(String detectorType, Map<String, List<String>> correlatedFindings, Finding orphanFinding) {
            long findingTimestamp = this.request.getFinding().getTimestamp().toEpochMilli();
            BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                    .mustNot(QueryBuilders.termQuery("scoreTimestamp", 0L));
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(queryBuilder);
            searchSourceBuilder.fetchSource(true);
            searchSourceBuilder.size(1);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
            searchRequest.source(searchSourceBuilder);

            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    String id = response.getHits().getHits()[0].getId();
                    Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
                    long scoreTimestamp = (long) hitSource.get("scoreTimestamp");

                    if (findingTimestamp - CorrelationIndices.FIXED_HISTORICAL_INTERVAL > scoreTimestamp) {
                        try {
                            XContentBuilder scoreBuilder = XContentFactory.jsonBuilder().startObject();
                            scoreBuilder.field("scoreTimestamp", findingTimestamp - CorrelationIndices.FIXED_HISTORICAL_INTERVAL);
                            scoreBuilder.field("root", false);
                            scoreBuilder.endObject();

                            IndexRequest scoreIndexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                    .id(id)
                                    .source(scoreBuilder)
                                    .timeout(indexTimeout)
                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                            client.index(scoreIndexRequest, new ActionListener<>() {
                                @Override
                                public void onResponse(IndexResponse response) {
                                    if (correlatedFindings != null) {
                                        if (correlatedFindings.isEmpty()) {
                                            insertOrphanFindings(detectorType, request.getFinding(), Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue());
                                        }
                                        for (Map.Entry<String, List<String>> correlatedFinding : correlatedFindings.entrySet()) {
                                            insertCorrelatedFindings(detectorType, request.getFinding(), correlatedFinding.getKey(), correlatedFinding.getValue(),
                                                    Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue());
                                        }
                                    } else {
                                        insertOrphanFindings(detectorType, orphanFinding, Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue());
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            });
                        } catch (Exception ex) {
                            onFailures(ex);
                        }
                    } else {
                        float timestampFeature = Long.valueOf((findingTimestamp - scoreTimestamp) / 1000L).floatValue();
                        if (correlatedFindings != null) {
                            if (correlatedFindings.isEmpty()) {
                                insertOrphanFindings(detectorType, request.getFinding(), timestampFeature);
                            }
                            for (Map.Entry<String, List<String>> correlatedFinding : correlatedFindings.entrySet()) {
                                insertCorrelatedFindings(detectorType, request.getFinding(), correlatedFinding.getKey(), correlatedFinding.getValue(),
                                        timestampFeature);
                            }
                        } else {
                            insertOrphanFindings(detectorType, orphanFinding, timestampFeature);
                        }
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        private void onOperation() {
            this.response.set(RestStatus.OK);
            if (counter.compareAndSet(false, true)) {
                finishHim(null);
            }
        }

        private void onFailures(Exception t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(t);
            }
        }

        private void finishHim(Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new CorrelateFindingsResponse(RestStatus.OK);
                }
            }));
        }
    }

    static class DocSearchCriteria {
        String index;
        String parentIndex;
        List<String> relatedDocIds;
        String joinKey;
        Object joinValue;
        String parentJoinKey;
        Object parentJoinValue;
        Boolean isQuery;

        public DocSearchCriteria(String index, String joinKey, Object joinValue, List<String> relatedDocIds, String parentIndex, String parentJoinKey, Object parentJoinValue, Boolean isQuery) {
            this.index = index;
            this.joinKey = joinKey;
            this.joinValue = joinValue;
            this.relatedDocIds = relatedDocIds;
            this.parentIndex = parentIndex;
            this.parentJoinKey = parentJoinKey;
            this.parentJoinValue = parentJoinValue;
            this.isQuery = isQuery;
        }
    }

    static class ParentJoinCriteria {
        String category;
        String index;
        String parentJoinKey;
        Object parentJoinValue;
        Boolean isQuery;

        public ParentJoinCriteria(String category, String index, String parentJoinKey, Object parentJoinValue, Boolean isQuery) {
            this.category = category;
            this.index = index;
            this.parentJoinKey = parentJoinKey;
            this.parentJoinValue = parentJoinValue;
            this.isQuery = isQuery;
        }
    }

    private CorrelateFindingsRequest transformRequest(ActionRequest request) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStreamStreamOutput osso = new OutputStreamStreamOutput(baos);
        request.writeTo(osso);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        InputStreamStreamInput issi = new InputStreamStreamInput(bais);
        return new CorrelateFindingsRequest(issi);
    }
}