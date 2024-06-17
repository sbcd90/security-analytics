/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model.threatintel;

import org.opensearch.commons.alerting.model.FindingDocument;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class IocMatchWithDocs implements Writeable, ToXContent {

    private static final String IOC_MATCH_FIELD = "ioc_finding";

    private static final String DOCUMENTS_FIELD = "document_list";

    private IocMatch iocMatch;

    private List<FindingDocument> documents;

    public IocMatchWithDocs(IocMatch iocMatch, List<FindingDocument> documents) {
        super();
        this.iocMatch = iocMatch;
        this.documents = documents;
    }

    public IocMatchWithDocs(StreamInput sin) throws IOException {
        this(
                IocMatch.readFrom(sin),
                sin.readList(FindingDocument::readFrom)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        iocMatch.writeTo(out);
        out.writeCollection(documents);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(IOC_MATCH_FIELD, iocMatch)
                .field(DOCUMENTS_FIELD, documents);
        return builder.endObject();
    }

    public static IocMatchWithDocs parse(XContentParser xcp) throws IOException {
        IocMatch iocMatch = null;
        List<FindingDocument> documents = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case IOC_MATCH_FIELD:
                    iocMatch = IocMatch.parse(xcp);
                    break;
                case DOCUMENTS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        documents.add(FindingDocument.parse(xcp));
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new IocMatchWithDocs(iocMatch, documents);
    }

    public static IocMatchWithDocs readFrom(StreamInput sin) throws IOException {
        return new IocMatchWithDocs(sin);
    }
}