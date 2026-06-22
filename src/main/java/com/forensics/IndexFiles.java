package com.forensics;

import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.*;
import org.apache.lucene.index.*;
import org.apache.lucene.store.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;

public class IndexFiles {

    public static String getSHA256(File file) throws Exception {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(fileBytes);

        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Directory dir = FSDirectory.open(Paths.get("index"));
        StandardAnalyzer analyzer = new StandardAnalyzer();

        IndexWriterConfig config = new IndexWriterConfig(analyzer);
        config.setOpenMode(IndexWriterConfig.OpenMode.CREATE);

        IndexWriter writer = new IndexWriter(dir, config);

        File folder = new File("evidence");

        for (File file : folder.listFiles()) {
            if (!file.isFile()) continue;

            String content = new String(Files.readAllBytes(file.toPath()));
            String sha256 = getSHA256(file);

            String fileName = file.getName();

            String extension = "";
            int dotIndex = fileName.lastIndexOf(".");
            if (dotIndex > 0) {
                extension = fileName.substring(dotIndex + 1).toLowerCase();
            }

            Document doc = new Document();

            // Content
            doc.add(new TextField("content", content, Field.Store.YES));

            // Basic file info
            doc.add(new StringField("filename", fileName, Field.Store.YES));
            doc.add(new StringField("filepath", file.getAbsolutePath(), Field.Store.YES));
            doc.add(new StringField("extension", extension, Field.Store.YES));

            // Forensic metadata
            doc.add(new StoredField("filesize", file.length()));
            doc.add(new StoredField("lastModified", file.lastModified()));
            doc.add(new StringField("sha256", sha256, Field.Store.YES));

            writer.addDocument(doc);

            System.out.println("Indexed: " + fileName);
        }

        writer.close();
        System.out.println("Indexing complete.");
    }
}