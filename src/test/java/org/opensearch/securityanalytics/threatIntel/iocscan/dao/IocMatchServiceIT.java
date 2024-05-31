package org.opensearch.securityanalytics.threatIntel.iocscan.dao;

import org.opensearch.action.LatchedActionListener;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.SecurityAnalyticsIntegTestCase;
import org.opensearch.securityanalytics.model.threatintel.IocMatch;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;


public class IocMatchServiceIT extends SecurityAnalyticsIntegTestCase {

    public void test_indexIocMatches() {
        IocMatchService service = new IocMatchService(client(), clusterService());
        List<IocMatch> iocMatches = generateIocMatches(10);
        CountDownLatch latch = new CountDownLatch(1);
        service.indexIocMatches(iocMatches, new LatchedActionListener<>(new ActionListener<>() {
            @Override
            public void onResponse(Void unused) {
                client().search(new SearchRequest(IocMatchService.INDEX_NAME)).
            }

            @Override
            public void onFailure(Exception e) {
                logger.error("failed to index ioc matches", e);
                fail();
            }
        }, latch));
    }

    private List<IocMatch> generateIocMatches(int i) {
        List<IocMatch> iocMatches = new ArrayList<>();
        String monitorId = randomAlphaOfLength(10);
        String monitorName = randomAlphaOfLength(10);
        for (int i1 = 0; i1 < i; i1++) {
            iocMatches.add(new IocMatch(
                    randomAlphaOfLength(10),
                    randomList(1,10, () -> randomAlphaOfLength(10)),//docids
                    randomList(1,10, () -> randomAlphaOfLength(10)), //feedids
                    monitorId,
                    monitorName,
                    randomAlphaOfLength(10),
                    "IP",
                    Instant.now(),
                    randomAlphaOfLength(10)
            ));
        }
        return iocMatches;
    }
}