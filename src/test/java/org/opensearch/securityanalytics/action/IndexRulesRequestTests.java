/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.UUID;

public class IndexRulesRequestTests extends OpenSearchTestCase {

    public void testIndexRulesPostRequest() throws IOException {
/*        IndexDetectorRequest request = new IndexDetectorRequest(UUID.randomUUID().toString(), WriteRequest.RefreshPolicy.IMMEDIATE, RestRequest.Method.POST, );

        Assert.assertNotNull(request);

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IndexDetectorRequest newRequest = new IndexDetectorRequest(sin);
        Assert.assertEquals(RestRequest.Method.POST, newRequest.getMethod());*/
    }
}