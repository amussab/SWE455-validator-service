import unittest

from validation import ACCEPTED, REJECTED, SUSPICIOUS, validate_file


class ValidationTests(unittest.TestCase):
    def test_accepts_valid_pdf(self):
        result = validate_file(
            filename="report.pdf",
            claimed_content_type="application/pdf",
            size_bytes=120,
            content_sample=b"%PDF-1.7\ncontent",
            max_size_bytes=1024,
        )

        self.assertEqual(result.status, ACCEPTED)
        self.assertEqual(result.detected_type, "application/pdf")

    def test_rejects_unsupported_extension(self):
        result = validate_file(
            filename="script.sh",
            claimed_content_type="text/plain",
            size_bytes=20,
            content_sample=b"#!/bin/sh",
            max_size_bytes=1024,
        )

        self.assertEqual(result.status, REJECTED)
        self.assertIn("not allowed", result.reason)

    def test_rejects_large_file(self):
        result = validate_file(
            filename="image.png",
            claimed_content_type="image/png",
            size_bytes=2048,
            content_sample=b"\x89PNG\r\n\x1a\n",
            max_size_bytes=1024,
        )

        self.assertEqual(result.status, REJECTED)
        self.assertIn("size exceeded", result.reason)

    def test_flags_executable_renamed_as_pdf(self):
        result = validate_file(
            filename="report.pdf",
            claimed_content_type="application/pdf",
            size_bytes=200,
            content_sample=b"MZ\x90\x00",
            max_size_bytes=1024,
        )

        self.assertEqual(result.status, SUSPICIOUS)
        self.assertTrue(result.suspicious)
        self.assertIn("spoofing", result.reason)

    def test_rejects_mime_mismatch(self):
        result = validate_file(
            filename="report.pdf",
            claimed_content_type="image/png",
            size_bytes=200,
            content_sample=b"%PDF-1.7\ncontent",
            max_size_bytes=1024,
        )

        self.assertEqual(result.status, REJECTED)
        self.assertIn("MIME type", result.reason)

    def test_allows_generic_s3_content_type_when_magic_bytes_match(self):
        result = validate_file(
            filename="report.pdf",
            claimed_content_type="application/octet-stream",
            size_bytes=200,
            content_sample=b"%PDF-1.7\ncontent",
            max_size_bytes=1024,
        )

        self.assertEqual(result.status, ACCEPTED)

    def test_accepts_valid_csv(self):
        result = validate_file(
            filename="records.csv",
            claimed_content_type="text/csv",
            size_bytes=30,
            content_sample=b"name,age\nAli,22\nSara,21\n",
            max_size_bytes=1024,
        )

        self.assertEqual(result.status, ACCEPTED)
        self.assertEqual(result.detected_type, "text/csv")

    def test_rejects_invalid_csv_shape(self):
        result = validate_file(
            filename="records.csv",
            claimed_content_type="text/csv",
            size_bytes=30,
            content_sample=b"name,age\nAli\nSara,21\n",
            max_size_bytes=1024,
        )

        self.assertEqual(result.status, REJECTED)
        self.assertIn("CSV", result.reason)


if __name__ == "__main__":
    unittest.main()
