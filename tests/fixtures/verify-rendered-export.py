import hashlib,json,pathlib,subprocess,sys,xml.etree.ElementTree as ET,zipfile
root=pathlib.Path(sys.argv[1])
with zipfile.ZipFile(root/'package.zip') as z:
    assert z.testzip() is None
    assert z.namelist()==['verification.json','verification.pdf','manifest.json']
    manifest=json.loads(z.read('manifest.json'))
    for entry in manifest['files']:
        buf=z.read(entry['name'])
        assert len(buf)==entry['bytes']
        assert hashlib.sha256(buf).hexdigest()==entry['sha256']
    report=json.loads(z.read('verification.json'))
    pdf=root/'verification.pdf'
    pdf.write_bytes(z.read('verification.pdf'))
subprocess.run(['pdfinfo',str(pdf)],check=True)
subprocess.run(['pdftoppm','-r','72','-f','1','-l','1','-png',str(pdf),str(root/'preview')],check=True)
assert list(root.glob('preview-*.png'))
xml=root/'boxes.xml'
subprocess.run(['pdftotext','-bbox',str(pdf),str(xml)],check=True)
tree=ET.parse(xml)
pages=tree.findall('.//{*}page')
assert len(pages)>3
for page in pages:
    for word in page.findall('.//{*}word'):
        assert 35<=float(word.attrib['xMin'])<=float(word.attrib['xMax'])<=560,word.attrib
        assert 12<=float(word.attrib['yMin'])<=float(word.attrib['yMax'])<=830,word.attrib
content=subprocess.check_output(['pdftotext',str(pdf),'-'],text=True)
for row in report['evidence']+report['reviews']:
    assert row['id'] in content,row['id']
assert hashlib.sha256(json.dumps(report,separators=(',',':'),ensure_ascii=False).encode()).hexdigest() in content
assert 'UNSIGNED DATABASE SNAPSHOT' in content
print('independent_pdf_render_and_zip_integrity_gate_passed')
