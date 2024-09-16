import pytest
import shutil
from tempfile import NamedTemporaryFile
from docx_locker import apply_docx_protection, get_docx_protection
from zipfile import ZipFile
from lxml import etree


@pytest.mark.parametrize(
    "doc_path, password",
    [
        ("tests/test_files/test.docx", "password"),
        ("../\\/test/test,docx", "password"),
    ]
)
def test_apply_docx_protection_invalid_file(doc_path, password):
    with pytest.raises(FileNotFoundError):
        apply_docx_protection(doc_path, password)


@pytest.mark.parametrize(
    "doc_path",
    [
        ("tests/test_files/test.docx"),
        ("../\\/test/test,docx"),
    ]
)
def test_get_docx_protection_invalid_file(doc_path):
    with pytest.raises(FileNotFoundError):
        get_docx_protection(doc_path)


@pytest.fixture
def known_word_protection():
    return {
        'doc_path': 'tests/test_files/protected.docx',
        'edit_option': 'trackedChanges',
        'enforce_option': '1',
        'crypt_provider_type': 'rsaAES',
        'crypt_algorithm_class': 'hash',
        'crypt_algorithm_type': 'typeAny',
        'crypt_algorithm_sid': 14,
        'crypt_spin_count': 100000,
        'hash': 'Zny9LoLNIRJagio+ZT7YYLp4WKoieHQx7ggU0hQ795TjtK05LUATM3/R4CXLv6+BnWejpDbdkbtKL9HdfdWOnw==',
        'salt': 'SKP/sgkziAF2G67DFMGFuQ=='
    }


def test_get_docx_protection_with_protected_doc(known_word_protection):
    case = get_docx_protection(known_word_protection['doc_path'])
    assert case.edit_option == known_word_protection['edit_option'], "Edit option does not match expected value"
    assert case.enforce_option == known_word_protection['enforce_option'], "Enforce option does not match expected value"
    assert case.crypt_provider_type == known_word_protection['crypt_provider_type'], "Crypt provider type does not match expected value"
    assert case.crypt_algorithm_class == known_word_protection['crypt_algorithm_class'], "Crypt algorithm class does not match expected value"
    assert case.crypt_algorithm_type == known_word_protection['crypt_algorithm_type'], "Crypt algorithm type does not match expected value"
    assert case.crypt_algorithm_sid == known_word_protection['crypt_algorithm_sid'], "Crypt algorithm SID does not match expected value"
    assert case.crypt_spin_count == known_word_protection['crypt_spin_count'], "Crypt spin count does not match expected value"
    assert case.hash_value == known_word_protection['hash'], "Hash does not match expected value"
    assert case.salt_value == known_word_protection['salt'], "Salt does not match expected value"


def test_get_docx_protection_with_unprotected_doc():
    case = get_docx_protection("tests/test_files/unprotected.docx")
    assert case is None, "Protection settings should be empty for an unprotected document"


@pytest.fixture
def unprotected_doc_path():
    return "tests/test_files/unprotected.docx"


@pytest.fixture
def protected_doc_path():
    return "tests/test_files/protected.docx"


def test_apply_docx_protection_to_unprotected_doc(unprotected_doc_path):
    # Use NamedTemporaryFile in the with statement to ensure it's properly cleaned up
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        # Copy the unprotected document to the temp file
        shutil.copyfile(unprotected_doc_path, temp_file.name)

        # Apply protection with a sample password
        password = "new_password"
        apply_docx_protection(temp_file.name, password)

        # Retrieve the applied protection settings
        protection_settings = get_docx_protection(temp_file.name)

        assert protection_settings is not None, "Protection settings should not be None after applying protection"
        assert protection_settings.edit_option == "trackedChanges", "Edit option should be TrackedChanges"
        assert protection_settings.enforce_option == '1', "Enforce option should be enabled (1)"
        assert protection_settings.crypt_provider_type == 'rsaAES', "Crypt provider type should be rsaAES"
        assert protection_settings.hash_value is not None, "Hash value should be set"
        assert protection_settings.salt_value is not None, "Salt value should be set"


def test_apply_docx_protection_to_protected_doc(protected_doc_path):
    # Use NamedTemporaryFile in the with statement to ensure it's properly cleaned up
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        # Copy the protected document to the temp file
        shutil.copyfile(protected_doc_path, temp_file.name)

        # Apply protection with a new password
        new_password = "updated_password"
        apply_docx_protection(temp_file.name, new_password, edit_option="readOnly")

        # Retrieve the newly applied protection settings
        protection_settings = get_docx_protection(temp_file.name)

        assert protection_settings is not None, "Protection settings should not be None after reapplying protection"
        assert protection_settings.edit_option == "readOnly", "Edit option should be readOnly"
        assert protection_settings.enforce_option == '1', "Enforce option should be enabled (1)"
        assert protection_settings.crypt_provider_type == 'rsaAES', "Crypt provider type should still be rsaAES"


def test_apply_docx_protection_to_protected_doc_with_hash(protected_doc_path):
    # Use NamedTemporaryFile in the with statement to ensure it's properly cleaned up
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        # Copy the protected document to the temp file
        shutil.copyfile(protected_doc_path, temp_file.name)

        # Apply protection with a new password and provided salt
        new_password = "updated_password"
        apply_docx_protection(temp_file.name, new_password, salt='ouz9XiaimAE4pO6OOtk28g==', edit_option="readOnly")

        # Retrieve the newly applied protection settings
        protection_settings = get_docx_protection(temp_file.name)

        assert protection_settings is not None, "Protection settings should not be None after reapplying protection"
        assert protection_settings.edit_option == "readOnly", "Edit option should be readOnly"
        assert protection_settings.enforce_option == '1', "Enforce option should be enabled (1)"
        assert protection_settings.crypt_provider_type == 'rsaAES', "Crypt provider type should still be rsaAES"
        assert protection_settings.salt_value == 'ouz9XiaimAE4pO6OOtk28g==', "Salt does not match expected value"


def test_apply_docx_protection_with_return_protection_params():
    # Use NamedTemporaryFile to create a temporary DOCX
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        # Create an unprotected DOCX
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:settings>')
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Apply protection with return_protection_params=True
        password = "password"
        protection_params = apply_docx_protection(temp_file.name, password, return_protection_params=True)

        assert protection_params is not None, "Protection parameters should be returned when requested"
        assert protection_params.edit_option == "trackedChanges", "Edit option should be trackedChanges"
        assert protection_params.enforce_option == '1', "Enforce option should be enabled (1)"
        assert protection_params.crypt_provider_type == 'rsaAES', "Crypt provider type should be rsaAES"
        assert protection_params.hash_value is not None, "Hash value should be set"
        assert protection_params.salt_value is not None, "Salt value should be set"


def test_get_docx_protection_no_document_protection():
    # Create a temporary DOCX with settings.xml but no documentProtection
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        settings_xml = '''
        <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:trackRevisions w:val="true"/>
        </w:settings>
        '''
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', settings_xml)
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Attempt to get protection settings
        protection = get_docx_protection(temp_file.name)
        assert protection is None, "Protection settings should be None when documentProtection element is missing"


def test_apply_docx_protection_existing_document_protection():
    # Create a temporary DOCX with existing documentProtection
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        settings_xml = '''
        <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:documentProtection w:edit="comments" w:enforcement="1"
                w:cryptProviderType="rsaAES" w:cryptAlgorithmClass="hash"
                w:cryptAlgorithmType="typeAny" w:cryptAlgorithmSid="14"
                w:cryptSpinCount="100000"
                w:hash="existingHash=="
                w:salt="existingSalt=="/>
            <w:trackRevisions w:val="true"/>
        </w:settings>
        '''
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', settings_xml)
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Apply protection with new parameters
        password = "new_password"
        apply_docx_protection(temp_file.name, password, edit_option="forms")

        # Retrieve the applied protection settings
        protection_settings = get_docx_protection(temp_file.name)
        assert protection_settings is not None, "Protection settings should not be None after reapplying protection"
        assert protection_settings.edit_option == "forms", "Edit option should be forms"
        assert protection_settings.enforce_option == '1', "Enforce option should be enabled (1)"
        assert protection_settings.crypt_provider_type == 'rsaAES', "Crypt provider type should still be rsaAES"
        assert protection_settings.hash_value != "existingHash==", "Hash should be updated"
        assert protection_settings.salt_value != "existingSalt==", "Salt should be updated"


def test_apply_docx_protection_with_invalid_settings_xml():
    # Create a temporary DOCX with invalid settings.xml
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        invalid_settings_xml = '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:documentProtection></w:settings>'
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', invalid_settings_xml)
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Attempt to apply protection, expecting an XML parsing error
        with pytest.raises(etree.XMLSyntaxError):
            apply_docx_protection(temp_file.name, "password")


def test_apply_docx_protection_with_missing_trackRevisions():
    # Create a temporary DOCX with settings.xml but without trackRevisions
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        settings_xml = '''
        <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">
        </w:settings>
        '''
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', settings_xml)
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Apply protection
        password = "password"
        apply_docx_protection(temp_file.name, password)

        # Retrieve the applied protection settings
        protection_settings = get_docx_protection(temp_file.name)
        assert protection_settings is not None, "Protection settings should not be None after applying protection"
        assert protection_settings.edit_option == "trackedChanges", "Edit option should be trackedChanges"
        assert protection_settings.enforce_option == '1', "Enforce option should be enabled (1)"


def test_apply_docx_protection_with_existing_mc_ignorable():
    # Create a temporary DOCX with settings.xml containing mc:Ignorable
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        settings_xml = '''
        <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
                    mc:Ignorable="w14">
            <w:trackRevisions w:val="true"/>
        </w:settings>
        '''
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', settings_xml)
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Apply protection
        password = "password"
        apply_docx_protection(temp_file.name, password)

        # Read back settings.xml to verify mc:Ignorable was updated
        with ZipFile(temp_file.name, 'r') as docx:
            modified_settings = docx.read('word/settings.xml')
            tree = etree.fromstring(modified_settings)
            namespaces = tree.nsmap
            mc_ignorable = tree.get(f'{{{namespaces["mc"]}}}Ignorable')
            assert mc_ignorable is not None, "mc:Ignorable attribute should exist"
            required_values = {'w14', 'w15', 'w16se'}
            existing_values = set(mc_ignorable.split())
            assert required_values.issubset(existing_values), "mc:Ignorable should include required values"


def test_apply_docx_protection_with_no_mc_namespace():
    # Create a temporary DOCX with settings.xml without mc namespace
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        settings_xml = '''
        <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:trackRevisions w:val="true"/>
        </w:settings>
        '''
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', settings_xml)
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Apply protection
        password = "password"
        apply_docx_protection(temp_file.name, password)

        # Read back settings.xml to verify mc:Ignorable was not added
        with ZipFile(temp_file.name, 'r') as docx:
            modified_settings = docx.read('word/settings.xml')
            tree = etree.fromstring(modified_settings)
            namespaces = tree.nsmap
            assert 'mc' not in namespaces, "mc namespace should not be present if it was not originally"


def test_apply_docx_protection_preserves_other_files():
    # Create a temporary DOCX with additional files
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:settings>')
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')
            docx.writestr('word/theme/theme1.xml', '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"></a:theme>')

        # Apply protection
        password = "password"
        apply_docx_protection(temp_file.name, password)

        # Verify that additional files are still present
        with ZipFile(temp_file.name, 'r') as docx:
            assert 'word/theme/theme1.xml' in docx.namelist(), "Additional files should be preserved after applying protection"


def test_apply_docx_protection_with_custom_parameters():
    # Create a temporary DOCX
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        with ZipFile(temp_file, 'w') as docx:
            settings_xml = '''
            <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">
                <w:trackRevisions w:val="true"/>
            </w:settings>
            '''
            docx.writestr('word/settings.xml', settings_xml)
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Apply protection with custom parameters
        password = "custom_password"
        apply_docx_protection(
            temp_file.name,
            password,
            edit_option="forms",
            enforce_option=0,
            return_protection_params=True
        )

        # Retrieve and verify the protection settings
        protection_settings = get_docx_protection(temp_file.name)
        assert protection_settings is not None, "Protection settings should not be None after applying protection"
        assert protection_settings.edit_option == "forms", "Edit option should be forms"
        assert protection_settings.enforce_option == '0', "Enforce option should be disabled (0)"


def test_apply_docx_protection_with_empty_password():
    # Create a temporary DOCX
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:settings>')
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Apply protection with an empty password
        password = ""
        apply_docx_protection(temp_file.name, password)

        # Retrieve the applied protection settings
        protection_settings = get_docx_protection(temp_file.name)
        assert protection_settings is not None, "Protection settings should not be None after applying protection"
        assert protection_settings.hash_value is not None, "Hash value should be set even with empty password"
        assert protection_settings.salt_value is not None, "Salt value should be set even with empty password"


def test_apply_docx_protection_with_large_password():
    # Create a temporary DOCX
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/settings.xml', '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:settings>')
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')

        # Apply protection with a large password
        password = "p" * 1000  # Very long password
        apply_docx_protection(temp_file.name, password)

        # Retrieve the applied protection settings
        protection_settings = get_docx_protection(temp_file.name)
        assert protection_settings is not None, "Protection settings should not be None after applying protection"
        assert len(protection_settings.hash_value) > 0, "Hash value should be set for large password"
        assert len(protection_settings.salt_value) > 0, "Salt value should be set for large password"
