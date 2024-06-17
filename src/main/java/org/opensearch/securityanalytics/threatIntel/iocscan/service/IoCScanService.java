package org.opensearch.securityanalytics.threatIntel.iocscan.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.IocScanContext;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeFieldMappings;
import org.opensearch.securityanalytics.threatIntel.iocscan.model.Ioc;
import org.opensearch.securityanalytics.threatIntel.iocscan.model.IocScanMonitor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiConsumer;


public abstract class IoCScanService<Data> implements IoCScanServiceInterface<Data> {
    private static final Logger log = LogManager.getLogger(IoCScanService.class);

    @Override
    public void scanIoCs(IocScanContext<Data> iocScanContext,
                         BiConsumer<Object, Exception> scanCallback
    ) {
        List<Data> data = iocScanContext.getData();
        IocScanMonitor iocScanMonitor = iocScanContext.getMonitor();

        long start = System.currentTimeMillis();
        // log.debug("beginning to scan IoC's")
        IocLookupDtos iocLookupDtos = extractIocPerTypeSet(data, iocScanMonitor.getIocTypeToIndexFieldMappings());
        BiConsumer<List<Ioc>, Exception> iocScanResultConsumer = (List<Ioc> maliciousIocs, Exception e) -> {
            if (e == null) {
                createIoCMatches(maliciousIocs, iocLookupDtos.iocValueToDocIdMap, iocScanContext,
                        new BiConsumer<List<Ioc>, Exception>() {
                            @Override
                            public void accept(List<Ioc> iocs, Exception e) {
                                createFindings(maliciousIocs, iocLookupDtos.docIdToIocsMap, iocScanMonitor);
                            }
                        }
                );

            } else {
                //                onIocMatchFailure(e, iocScanMonitor);

            }
        };
        matchAgainstThreatIntelAndReturnMaliciousIocs(iocLookupDtos.getIocsPerIocTypeMap(), iocScanMonitor, iocScanResultConsumer);
    }

    abstract void matchAgainstThreatIntelAndReturnMaliciousIocs(
            Map<String, Set<String>> iocPerTypeSet,
            IocScanMonitor iocScanMonitor,
            BiConsumer<List<Ioc>, Exception> callback);

    /**
     * For each doc, we extract the list of
     */
    private IocLookupDtos extractIocPerTypeSet(List<Data> data, List<PerIocTypeFieldMappings> iocTypeToIndexFieldMappings) {
        Map<String, Set<String>> iocsPerIocTypeMap = new HashMap<>();
        Map<String, Set<String>> iocValueToDocIdMap = new HashMap<>();
        Map<String, Set<String>> docIdToIocsMap = new HashMap<>();
        for (Data datum : data) {
            for (PerIocTypeFieldMappings iocTypeToIndexFieldMapping : iocTypeToIndexFieldMappings) {
                String iocType = iocTypeToIndexFieldMapping.getIocType();
                String index = getIndexName(datum);
                List<String> fields = iocTypeToIndexFieldMapping.getIndexToFieldsMap().get(index);
                for (String field : fields) {
                    List<String> vals = getValuesAsStringList(datum, field);
                    String id = getId(datum);
                    String indexName = getIndexName(datum);
                    String docId = id + ":" + indexName;
                    Set<String> iocs = docIdToIocsMap.getOrDefault(docIdToIocsMap.get(docId), new HashSet<>());
                    iocs.addAll(vals);
                    docIdToIocsMap.put(docId, iocs);
                    for (String ioc : vals) {
                        Set<String> docIds = iocValueToDocIdMap.getOrDefault(iocValueToDocIdMap.get(ioc), new HashSet<>());
                        docIds.add(docId);
                        iocValueToDocIdMap.put(ioc, docIds);
                    }
                    if (false == vals.isEmpty()) {
                        iocs = iocsPerIocTypeMap.getOrDefault(iocType, new HashSet<>());
                        iocs.addAll(vals);
                        iocsPerIocTypeMap.put(iocType, iocs);
                    }
                }
            }
        }
        return new IocLookupDtos(iocsPerIocTypeMap, iocValueToDocIdMap, docIdToIocsMap);
    }

    public abstract List<String> getValuesAsStringList(Data datum, String field);

    public abstract String getIndexName(Data datum);

    public abstract String getId(Data datum);

    public void createIoCMatches(List<Ioc> iocs, Map<String, Set<String>> iocValueToDocIdMap, IocScanContext iocScanContext, BiConsumer<List<Ioc>, Exception> callback) {
        try {
            Instant timestamp = Instant.now();
            IocScanMonitor iocScanMonitor = iocScanContext.getMonitor();
            // Map to collect unique IocValue with their respective FeedIds
            Map<String, Set<String>> iocValueToFeedIds = new HashMap<>();

            for (Ioc ioc : iocs) {
                String iocValue = ioc.getIocValue();
                iocValueToFeedIds
                        .computeIfAbsent(iocValue, k -> new HashSet<>())
                        .add(ioc.getFeedId());
            }

            List<IocFinding> iocFindings = new ArrayList<>();

            for (Map.Entry<String, Set<String>> entry : iocValueToFeedIds.entrySet()) {
                String iocValue = entry.getKey();
                Set<String> feedIds = entry.getValue();

                List<String> relatedDocIds = new ArrayList<>(iocValueToDocIdMap.getOrDefault(iocValue, new HashSet<>()));
                List<String> feedIdsList = new ArrayList<>(feedIds);
                try {
                    IocFinding iocFinding = new IocFinding(
                            UUID.randomUUID().toString(), // Generating a unique ID
                            relatedDocIds,
                            feedIdsList,
                            iocScanMonitor.getId(),
                            iocScanMonitor.getName(),
                            iocValue,
                            iocs.stream().filter(i -> i.getIocValue().equals(iocValue)).findFirst().orElseThrow().getIocType(),
                            timestamp,
                            UUID.randomUUID().toString() // TODO execution ID
                    );
                    iocFindings.add(iocFinding);
                } catch (Exception e) {
                    log.error(String.format("skipping creating ioc match for %s due to unexpected failure.", entry.getKey()), e);
                }
            }
            saveIocs(iocs, callback);
        } catch (Exception e) {
            log.error(() -> new ParameterizedMessage("Failed to create ioc matches due to unexpected error {}", iocScanContext.getMonitor().getId()), e);
            callback.accept(null, e);
        }
    }

    abstract void saveIocs(List<Ioc> iocs, BiConsumer<List<Ioc>, Exception> callback);

    public List<Finding> createFindings(List<Ioc> iocs, Map<String, Set<String>> docIdToIocsMap, IocScanMonitor iocScanMonitor) {
        List<Finding> findings = new ArrayList<>();

        for (Map.Entry<String, Set<String>> entry : docIdToIocsMap.entrySet()) {
            String docId = entry.getKey();
            Set<String> iocValues = entry.getValue();

            List<String> iocStrings = new ArrayList<>(iocValues);

            Finding finding = new Finding(
                    UUID.randomUUID().toString(), // Generating a unique ID
                    Collections.singletonList(docId), // Singleton list for relatedDocIds
                    Collections.emptyList(), // Empty list for correlatedDocIds
                    iocScanMonitor.getId(),
                    iocScanMonitor.getName(),
                    "", // Index value, you may need to provide an actual value
                    Collections.emptyList(), // Empty list for docLevelQueries
//                    iocStrings, TODO add field in findings
                    Instant.now(), // Current timestamp
                    null // Setting executionId as null, you may adjust accordingly
            );

            findings.add(finding);
        }

        return findings;
    }


    private static class IocMatchDto {
        private final String iocValue;
        private final String iocType;
        private final List<Ioc> iocs;
        private final List<String> docIdsContainingIoc;

        public IocMatchDto(String iocValue, String iocType, List<Ioc> iocs, List<String> docIdsContainingIoc) {
            this.iocValue = iocValue;
            this.iocType = iocType;
            this.iocs = iocs;
            this.docIdsContainingIoc = docIdsContainingIoc;
        }

        public String getIocValue() {
            return iocValue;
        }

        public String getIocType() {
            return iocType;
        }

        public List<Ioc> getIocs() {
            return iocs;
        }

        public List<String> getDocIdsContainingIoc() {
            return docIdsContainingIoc;
        }
    }

    private static class IocLookupDtos {
        private final Map<String, Set<String>> iocsPerIocTypeMap;
        private final Map<String, Set<String>> iocValueToDocIdMap;
        private final Map<String, Set<String>> docIdToIocsMap;

        public IocLookupDtos(Map<String, Set<String>> iocsPerIocTypeMap, Map<String, Set<String>> iocValueToDocIdMap, Map<String, Set<String>> docIdToIocsMap) {
            this.iocsPerIocTypeMap = iocsPerIocTypeMap;
            this.iocValueToDocIdMap = iocValueToDocIdMap;
            this.docIdToIocsMap = docIdToIocsMap;
        }

        public Map<String, Set<String>> getIocsPerIocTypeMap() {
            return iocsPerIocTypeMap;
        }

        public Map<String, Set<String>> getIocValueToDocIdMap() {
            return iocValueToDocIdMap;
        }

        public Map<String, Set<String>> getDocIdToIocsMap() {
            return docIdToIocsMap;
        }
    }

}
