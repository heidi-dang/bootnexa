"""Fail-closed publisher-hash and ISO manifest parser tests, no Microsoft media."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE=Path(__file__).with_name("windows_iso_publisher_manifest.py")
spec=importlib.util.spec_from_file_location("bootnexa_publisher_manifest",MODULE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def page(rows):
    return ("<html><table>"+"".join(f"<tr><td>{k}</td><td>{v}</td></tr>"
                                  for k,v in rows)+"</table></html>").encode()

class PublisherManifestTest(unittest.TestCase):
    def test_exact_microsoft_locale_row_required(self):
        a="A"*64
        b="B"*64
        self.assertEqual(m.parse_official_html(page([
            ("English International  64-bit",a),("English 64-bit",b)
        ]),"English International 64-bit"),"a"*64)
        self.assertEqual(m.parse_official_html(page([
            ("English International 64-bit",a),("English 64-bit",b)
        ]),"English 64-bit"),"b"*64)
        for rows in ([],[("English International 64-bit","BAD")],
                     [("English International 64-bit",a)]*2):
            with self.assertRaises(m.Rejected):
                m.parse_official_html(page(rows),"English International 64-bit")
        with self.assertRaises(m.Rejected):
            m.parse_official_html(page([("French 64-bit",a)]),"French 64-bit")
        with self.assertRaises(m.Rejected):
            m.parse_official_html(b"\xff","English 64-bit")
    def test_no_user_supplied_external_reference_url_or_redirect(self):
        import urllib.request
        redirect=m.MicrosoftOnlyRedirect()
        req=urllib.request.Request(m.OFFICIAL_URL)
        for redirect_url in (
            "http://www.microsoft.com/en-au/software-download/windows11",
            "https://evil.example/software-download/windows11",
            "https://www.microsoft.com:8080/en-au/software-download/windows11",
            "https://www.microsoft.com.evil.example/software-download/windows11",
        ):
            with self.assertRaises(m.Rejected):
                redirect.redirect_request(req,None,302,"redirect",{},redirect_url)
        self.assertTrue(m.OFFICIAL_URL.startswith("https://www.microsoft.com/"))
    def test_namespace_rejects_traversal_duplicate_and_pseudo_ambiguity(self):
        for p in ("../evil", "/dev/sda","A\\B", "a//b", "a/./b",
                  "a/../b", "-option", "A/*", "a\x01b", "A/B/"+"x"*250):
            with self.assertRaises(m.Rejected,msg=p):
                m.checked_path(p)
        prelude="Path = sample.iso\nType = Iso\nPhysical Size = 2048\n\n----------\n"
        def file(path,size="3",folder="-"):
            return f"Path = {path}\nFolder = {folder}\nSize = {size}\nPacked Size = {size}\n"
        items,_=m.parse_listing((prelude+file("EFI",folder="+")+"\n"+
                                 file("EFI/BOOT/BOOTX64.EFI")+"\n"+
                                 file("[BOOT]/Boot-NoEmul.img")+"\n").encode(),None,2048)
        self.assertEqual(len(items),1)
        for tail in (
            file("Setup.exe")+"\n"+file("SETUP.EXE"),
            file("A/../B"),
            file("danger.iso",size=str(m.MAX_FILE+1)),
            file("x",size="not-a-number"),
        ):
            with self.assertRaises(m.Rejected):
                m.parse_listing((prelude+tail).encode(),None,2048)
    def test_checksum_and_source_validation_before_enumeration(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source=root/"fixture.iso"
            source.write_bytes(b"\0"*4096)
            digest=hashlib.sha256(source.read_bytes()).hexdigest()
            alias=root/"link.iso";alias.symlink_to(source)
            with self.assertRaises(m.Rejected):
                m.safe_regular(alias)
            with self.assertRaises(m.Rejected):
                m.safe_parent(alias)
            with self.assertRaises(m.Rejected):
                m.build_manifest(source,{"referenceSha256":"f"*64},minimum=0,
                                 require_windows=False,exe="/bin/false")
            with self.assertRaises(m.Rejected):
                m.build_manifest(source,{"referenceSha256":digest},minimum=0,
                                 require_windows=False,exe="/bin/false")
            self.assertEqual(m.file_sha(source,8192)[1],digest)

if __name__=="__main__":
    unittest.main()
