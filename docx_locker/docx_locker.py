from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO
from pathlib import Path
from typing import Literal
from lxml import etree
from lxml.etree import QName
from .encrypt import generate_docx_protection


def get_docx_protection(doc_path: str) -> dict:
    # Ensure the file exists
    doc_file = Path(doc_path)
    if not doc_file.exists():
        raise FileNotFoundError(f"The specified file does not exist: {doc_path}")

    # Unzip the file in memory
    with ZipFile(doc_file, 'r') as docx:
        if 'word/settings.xml' not in docx.namelist():
            return None

        # Read settings.xml
        settings_xml = docx.read('word/settings.xml')
        tree = etree.fromstring(settings_xml)

        # Extract namespaces from the document
        namespaces = tree.nsmap

        # Find the documentProtection element
        document_protection = tree.find('.//w:documentProtection', namespaces)
        if document_protection is not None:
            # Extract the protection settings using .get() to directly fetch attribute values
            protection_settings = {
                'edit_option': document_protection.get(f'{{{namespaces["w"]}}}edit'),  # Fetch the 'edit' attribute
                'enforce_option': document_protection.get(f'{{{namespaces["w"]}}}enforcement'),
                'cryptProviderType': document_protection.get(f'{{{namespaces["w"]}}}cryptProviderType'),
                'cryptAlgorithmClass': document_protection.get(f'{{{namespaces["w"]}}}cryptAlgorithmClass'),
                'cryptAlgorithmType': document_protection.get(f'{{{namespaces["w"]}}}cryptAlgorithmType'),
                'cryptAlgorithmSid': document_protection.get(f'{{{namespaces["w"]}}}cryptAlgorithmSid'),
                'cryptSpinCount': document_protection.get(f'{{{namespaces["w"]}}}cryptSpinCount'),
                'hash': document_protection.get(f'{{{namespaces["w"]}}}hash'),
                'salt': document_protection.get(f'{{{namespaces["w"]}}}salt')
            }
            return protection_settings
    return None


def apply_docx_protection(
    doc_path: str,
    password: str,
    salt: str = None,
    edit_option: Literal["forms", "none", "readOnly", "trackedChanges", "comments"] = "trackedChanges",
    enforce_option: Literal[0, 1] = 1
) -> None:
    # Ensure the file exists
    doc_file = Path(doc_path)
    if not doc_file.exists():
        raise FileNotFoundError(f"The specified file does not exist: {doc_path}")

    # Generate the encryption vars
    crypto_params = generate_docx_protection(password, salt)

    # Unzip the file in memory
    in_memory_zip = BytesIO()
    with ZipFile(doc_file, 'r') as docx:
        # Copy all files except the one we're going to modify
        with ZipFile(in_memory_zip, 'w', ZIP_DEFLATED) as temp_docx:
            for item in docx.infolist():
                if item.filename != 'word/settings.xml':
                    temp_docx.writestr(item, docx.read(item.filename))
                else:
                    # Read and modify the settings.xml file
                    settings_xml = docx.read('word/settings.xml')
                    parser = etree.XMLParser(remove_blank_text=False)
                    root = etree.fromstring(settings_xml, parser=parser)

                    # Get the namespace map from the root element
                    namespace_map = root.nsmap

                    # Get the 'w' namespace URI
                    NS_W = namespace_map.get('w', 'http://schemas.openxmlformats.org/wordprocessingml/2006/main')

                    # Get the 'mc' namespace URI if it exists
                    NS_MC = namespace_map.get('mc', 'http://schemas.openxmlformats.org/markup-compatibility/2006')

                    # Ensure mc:Ignorable attribute is preserved and updated
                    if NS_MC:
                        mc_ignorable_attr_name = f'{{{NS_MC}}}Ignorable'
                        mc_ignorable = root.attrib.get(mc_ignorable_attr_name, '')
                        # Ensure 'w14 w15 w16se' are in mc:Ignorable
                        required_mc_values = {'w14', 'w15', 'w16se'}
                        existing_mc_values = set(mc_ignorable.split())
                        missing_mc_values = required_mc_values - existing_mc_values
                        if missing_mc_values:
                            new_mc_ignorable = mc_ignorable + ' ' + ' '.join(missing_mc_values)
                            root.attrib[mc_ignorable_attr_name] = new_mc_ignorable.strip()

                    # Check if the <w:trackRevisions> element exists, if not, add it at the end of <w:settings>
                    track_changes = root.find('w:trackRevisions', namespaces=namespace_map)
                    if track_changes is None:
                        track_changes_element = etree.Element(QName(NS_W, 'trackRevisions'))
                        root.append(track_changes_element)

                    # Build the <w:documentProtection> element
                    document_protection_element = etree.Element(
                        QName(NS_W, 'documentProtection'),
                        attrib={
                            QName(NS_W, 'edit'): f'{edit_option}',
                            QName(NS_W, 'enforcement'): f'{enforce_option}',
                            QName(NS_W, 'cryptProviderType'): f'{crypto_params.provider_type}',
                            QName(NS_W, 'cryptAlgorithmClass'): f'{crypto_params.algo_class}',
                            QName(NS_W, 'cryptAlgorithmType'): f'{crypto_params.algo_type}',
                            QName(NS_W, 'cryptAlgorithmSid'): f'{crypto_params.algo_sid}',
                            QName(NS_W, 'cryptSpinCount'): f'{crypto_params.spin_count}',
                            QName(NS_W, 'hash'): f'{crypto_params.key_hash}',
                            QName(NS_W, 'salt'): f'{crypto_params.salt_hash}'
                        }
                    )
                    # Check if the <w:documentProtection> element exists, if not, insert it
                    document_protection = root.find('w:documentProtection', namespaces=namespace_map)
                    if document_protection is None:
                        # Insert after w:trackRevisions if it exists, else at the beginning
                        insert_index = 0
                        for idx, child in enumerate(root):
                            if child.tag == QName(NS_W, 'trackRevisions'):
                                insert_index = idx + 1
                                break
                        root.insert(insert_index, document_protection_element)
                    else:
                        # Replace the existing <w:documentProtection> element
                        root.replace(document_protection, document_protection_element)

                    # Convert the modified XML tree back to a string
                    modified_settings_xml = etree.tostring(
                        root, encoding='utf-8', xml_declaration=False, pretty_print=False)

                    # Write the modified settings.xml back into the archive
                    temp_docx.writestr('word/settings.xml', modified_settings_xml)

    # Write the in-memory ZIP buffer back to the original file
    with open(doc_file, 'wb') as f:
        f.write(in_memory_zip.getvalue())
