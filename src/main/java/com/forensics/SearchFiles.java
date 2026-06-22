package com.forensics;

import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.index.*;
import org.apache.lucene.queryparser.classic.MultiFieldQueryParser;
import org.apache.lucene.search.*;
import org.apache.lucene.store.*;

import java.nio.file.Paths;

public class SearchFiles {
    public static void main(String[] args) throws Exception {
        Directory dir = FSDirectory.open(Paths.get("index"));
        DirectoryReader reader = DirectoryReader.open(dir);
        IndexSearcher searcher = new IndexSearcher(reader);

        StandardAnalyzer analyzer = new StandardAnalyzer();

        String[] fields = {
                "content",
                "filename",
                "extension",
                "sha256"
        };

        MultiFieldQueryParser parser =
                new MultiFieldQueryParser(fields, analyzer);

        String keyword = args.length > 0 ? String.join(" ", args) : "bitcoin";

        Query query = parser.parse(keyword);

        TopDocs results = searcher.search(query, 20);

        if (results.totalHits.value == 0) {
            System.out.println("No matches found.");
        }

        for (ScoreDoc scoreDoc : results.scoreDocs) {
            var doc = searcher.doc(scoreDoc.doc);

            System.out.println("==================================");
            System.out.println("Filename       : " + doc.get("filename"));
            System.out.println("Extension      : " + doc.get("extension"));
            System.out.println("SHA256         : " + doc.get("sha256"));
            System.out.println("File Path      : " + doc.get("filepath"));
            System.out.println("Matched Content: " + doc.get("content"));
            System.out.println("==================================");
        }

        reader.close();
    }
}