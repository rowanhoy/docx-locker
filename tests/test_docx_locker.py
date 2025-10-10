import pytest
import shutil
from tempfile import NamedTemporaryFile
from io import BytesIO
from docx_locker import apply_docx_protection, apply_docx_protection_buffer, get_docx_protection
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


def test_apply_docx_protection_missing_settings_xml():
    """Test file-based function with missing word/settings.xml"""
    # Create a minimal DOCX without settings.xml
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        with ZipFile(temp_file, 'w') as docx:
            docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')
        
        # Should raise ValueError when settings.xml is missing
        with pytest.raises(ValueError, match="does not contain word/settings.xml"):
            apply_docx_protection(temp_file.name, "password")


# Tests for BytesIO functionality using apply_docx_protection_buffer

@pytest.fixture
def unprotected_doc_buffer(unprotected_doc_path):
    """Load unprotected doc into BytesIO buffer"""
    with open(unprotected_doc_path, 'rb') as f:
        return BytesIO(f.read())


def test_apply_docx_protection_buffer_basic(unprotected_doc_buffer):
    """Test basic BytesIO protection"""
    password = "test_password"
    output_buffer = apply_docx_protection_buffer(unprotected_doc_buffer, password)
    
    assert isinstance(output_buffer, BytesIO), "Output should be a BytesIO object"
    assert output_buffer.tell() == 0, "Output buffer should be positioned at the start"
    
    # Verify protection was applied by saving and checking
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        temp_file.write(output_buffer.read())
        temp_file.flush()
        
        protection_settings = get_docx_protection(temp_file.name)
        assert protection_settings is not None, "Protection settings should be applied"
        assert protection_settings.edit_option == "trackedChanges", "Edit option should be trackedChanges"
        assert protection_settings.hash_value is not None, "Hash value should be set"


def test_apply_docx_protection_buffer_with_return_params(unprotected_doc_buffer):
    """Test BytesIO with return_protection_params=True"""
    password = "test_password"
    result = apply_docx_protection_buffer(unprotected_doc_buffer, password, return_protection_params=True)
    
    assert isinstance(result, tuple), "Result should be a tuple when return_protection_params=True"
    assert len(result) == 2, "Result should contain BytesIO and DocxProtectionParams"
    
    output_buffer, params = result
    assert isinstance(output_buffer, BytesIO), "First element should be BytesIO"
    assert params.edit_option == "trackedChanges", "Protection params should have correct edit option"
    assert params.hash_value is not None, "Protection params should have hash value"
    assert params.salt_value is not None, "Protection params should have salt value"


def test_apply_docx_protection_buffer_custom_options(unprotected_doc_buffer):
    """Test BytesIO with custom protection options"""
    password = "test_password"
    output_buffer = apply_docx_protection_buffer(
        unprotected_doc_buffer,
        password,
        edit_option="readOnly",
        enforce_option=1
    )
    
    assert isinstance(output_buffer, BytesIO), "Output should be a BytesIO object"
    
    # Verify protection settings
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        temp_file.write(output_buffer.read())
        temp_file.flush()
        
        protection_settings = get_docx_protection(temp_file.name)
        assert protection_settings is not None, "Protection settings should be applied"
        assert protection_settings.edit_option == "readOnly", "Edit option should be readOnly"
        assert protection_settings.enforce_option == "1", "Enforce option should be 1"


def test_apply_docx_protection_buffer_with_salt(unprotected_doc_buffer):
    """Test BytesIO with custom salt"""
    password = "test_password"
    custom_salt = "ouz9XiaimAE4pO6OOtk28g=="
    output_buffer, params = apply_docx_protection_buffer(
        unprotected_doc_buffer,
        password,
        salt=custom_salt,
        return_protection_params=True
    )
    
    assert params.salt_value == custom_salt, "Salt should match the provided value"


def test_apply_docx_protection_buffer_preserves_input(unprotected_doc_path):
    """Test that the input BytesIO buffer is not modified"""
    with open(unprotected_doc_path, 'rb') as f:
        original_data = f.read()
        input_buffer = BytesIO(original_data)
    
    password = "test_password"
    output_buffer = apply_docx_protection_buffer(input_buffer, password)
    
    # The input buffer should still exist and be readable
    input_buffer.seek(0)
    input_data_after = input_buffer.read()
    
    # Input should be unchanged
    assert len(input_data_after) == len(original_data), "Input buffer data should be preserved"
    
    # Output should be different from input (since it's protected)
    output_buffer.seek(0)
    output_data = output_buffer.read()
    assert output_data != original_data, "Output should be different from input (protected)"


def test_apply_docx_protection_buffer_multiple_edits(unprotected_doc_buffer):
    """Test applying protection multiple times to different buffers"""
    password1 = "password1"
    password2 = "password2"
    
    # First protection
    buffer1 = apply_docx_protection_buffer(unprotected_doc_buffer, password1)
    
    # Reset input buffer for second protection
    unprotected_doc_buffer.seek(0)
    buffer2 = apply_docx_protection_buffer(unprotected_doc_buffer, password2)
    
    # Both should be valid but different
    assert buffer1.getvalue() != buffer2.getvalue(), "Different passwords should produce different results"


def test_apply_docx_protection_buffer_empty_password(unprotected_doc_buffer):
    """Test BytesIO with empty password"""
    password = ""
    output_buffer, params = apply_docx_protection_buffer(
        unprotected_doc_buffer,
        password,
        return_protection_params=True
    )
    
    assert params.hash_value is not None, "Hash value should be set even with empty password"
    assert params.salt_value is not None, "Salt value should be set even with empty password"


def test_apply_docx_protection_vs_buffer_same_result(unprotected_doc_path):
    """Test that file and buffer methods produce equivalent results"""
    password = "test_password"
    custom_salt = "ouz9XiaimAE4pO6OOtk28g=="
    
    # Apply to file
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        shutil.copyfile(unprotected_doc_path, temp_file.name)
        file_params = apply_docx_protection(
            temp_file.name,
            password,
            salt=custom_salt,
            return_protection_params=True
        )
    
    # Apply to buffer
    with open(unprotected_doc_path, 'rb') as f:
        buffer = BytesIO(f.read())
    buffer_output, buffer_params = apply_docx_protection_buffer(
        buffer,
        password,
        salt=custom_salt,
        return_protection_params=True
    )
    
    # Both should produce the same protection parameters
    assert file_params.hash_value == buffer_params.hash_value, "Hash values should match"
    assert file_params.salt_value == buffer_params.salt_value, "Salt values should match"
    assert file_params.edit_option == buffer_params.edit_option, "Edit options should match"


def test_apply_docx_protection_buffer_all_edit_options(unprotected_doc_buffer):
    """Test all edit option values work with buffer"""
    password = "test_password"
    edit_options = ["forms", "none", "readOnly", "trackedChanges", "comments"]
    
    for edit_option in edit_options:
        unprotected_doc_buffer.seek(0)  # Reset for each iteration
        output_buffer, params = apply_docx_protection_buffer(
            unprotected_doc_buffer,
            password,
            edit_option=edit_option,
            return_protection_params=True
        )
        assert params.edit_option == edit_option, f"Edit option should be {edit_option}"


def test_apply_docx_protection_buffer_invalid_zip():
    """Test buffer with invalid ZIP content"""
    invalid_buffer = BytesIO(b"This is not a valid ZIP file")
    
    with pytest.raises(Exception):  # Will raise BadZipFile or similar
        apply_docx_protection_buffer(invalid_buffer, "password")


def test_apply_docx_protection_buffer_missing_settings_xml():
    """Test buffer with missing word/settings.xml"""
    # Create a minimal DOCX without settings.xml
    buffer = BytesIO()
    with ZipFile(buffer, 'w') as docx:
        docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')
    
    buffer.seek(0)
    
    # Should raise ValueError when settings.xml is missing
    with pytest.raises(ValueError, match="does not contain word/settings.xml"):
        apply_docx_protection_buffer(buffer, "password")


def test_apply_docx_protection_buffer_invalid_settings_xml():
    """Test buffer with invalid settings.xml"""
    buffer = BytesIO()
    invalid_settings_xml = '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:documentProtection></w:settings>'
    
    with ZipFile(buffer, 'w') as docx:
        docx.writestr('word/settings.xml', invalid_settings_xml)
        docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')
    
    buffer.seek(0)
    
    # Should raise XML parsing error
    with pytest.raises(etree.XMLSyntaxError):
        apply_docx_protection_buffer(buffer, "password")


def test_apply_docx_protection_buffer_reprotect():
    """Test re-protecting an already protected buffer"""
    # Create a buffer with existing protection
    buffer = BytesIO()
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
    with ZipFile(buffer, 'w') as docx:
        docx.writestr('word/settings.xml', settings_xml)
        docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')
    
    buffer.seek(0)
    
    # Re-protect with new parameters
    password = "new_password"
    output_buffer, params = apply_docx_protection_buffer(
        buffer,
        password,
        edit_option="forms",
        return_protection_params=True
    )
    
    assert params.edit_option == "forms", "Edit option should be updated to forms"
    assert params.hash_value != "existingHash==", "Hash should be updated"
    assert params.salt_value != "existingSalt==", "Salt should be updated"


def test_apply_docx_protection_buffer_missing_trackRevisions():
    """Test buffer with settings.xml but without trackRevisions"""
    buffer = BytesIO()
    settings_xml = '''
    <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">
    </w:settings>
    '''
    with ZipFile(buffer, 'w') as docx:
        docx.writestr('word/settings.xml', settings_xml)
        docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')
    
    buffer.seek(0)
    
    # Should add trackRevisions element
    password = "password"
    output_buffer = apply_docx_protection_buffer(buffer, password)
    
    # Verify trackRevisions was added
    output_buffer.seek(0)
    with ZipFile(output_buffer, 'r') as docx:
        settings = docx.read('word/settings.xml')
        tree = etree.fromstring(settings)
        namespaces = tree.nsmap
        track_revisions = tree.find('w:trackRevisions', namespaces=namespaces)
        assert track_revisions is not None, "trackRevisions should be added"


def test_apply_docx_protection_buffer_with_mc_ignorable():
    """Test buffer with mc:Ignorable attribute"""
    buffer = BytesIO()
    settings_xml = '''
    <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
                mc:Ignorable="w14">
        <w:trackRevisions w:val="true"/>
    </w:settings>
    '''
    with ZipFile(buffer, 'w') as docx:
        docx.writestr('word/settings.xml', settings_xml)
        docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')
    
    buffer.seek(0)
    
    password = "password"
    output_buffer = apply_docx_protection_buffer(buffer, password)
    
    # Verify mc:Ignorable was updated
    output_buffer.seek(0)
    with ZipFile(output_buffer, 'r') as docx:
        modified_settings = docx.read('word/settings.xml')
        tree = etree.fromstring(modified_settings)
        namespaces = tree.nsmap
        mc_ignorable = tree.get(f'{{{namespaces["mc"]}}}Ignorable')
        assert mc_ignorable is not None, "mc:Ignorable attribute should exist"
        required_values = {'w14', 'w15', 'w16se'}
        existing_values = set(mc_ignorable.split())
        assert required_values.issubset(existing_values), "mc:Ignorable should include required values"


def test_apply_docx_protection_buffer_preserves_other_files():
    """Test that buffer method preserves other files in the archive"""
    buffer = BytesIO()
    with ZipFile(buffer, 'w') as docx:
        docx.writestr('word/settings.xml', '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:settings>')
        docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')
        docx.writestr('word/theme/theme1.xml', '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"></a:theme>')
        docx.writestr('word/media/image1.png', b'fake image data')
    
    buffer.seek(0)
    
    password = "password"
    output_buffer = apply_docx_protection_buffer(buffer, password)
    
    # Verify that additional files are preserved
    output_buffer.seek(0)
    with ZipFile(output_buffer, 'r') as docx:
        assert 'word/theme/theme1.xml' in docx.namelist(), "Theme file should be preserved"
        assert 'word/media/image1.png' in docx.namelist(), "Media file should be preserved"


def test_apply_docx_protection_buffer_enforce_option_zero():
    """Test buffer with enforce_option=0"""
    buffer = BytesIO()
    with ZipFile(buffer, 'w') as docx:
        settings_xml = '''
        <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">
            <w:trackRevisions w:val="true"/>
        </w:settings>
        '''
        docx.writestr('word/settings.xml', settings_xml)
        docx.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>')
    
    buffer.seek(0)
    
    password = "password"
    output_buffer, params = apply_docx_protection_buffer(
        buffer,
        password,
        enforce_option=0,
        return_protection_params=True
    )
    
    assert params.enforce_option == '0', "Enforce option should be 0"


def test_apply_docx_protection_file_then_buffer_reprotect(unprotected_doc_path):
    """Test protecting via file method, then re-protecting the result via buffer method"""
    # First protect via file method
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        shutil.copyfile(unprotected_doc_path, temp_file.name)
        apply_docx_protection(temp_file.name, "password1", edit_option="readOnly")
        
        # Load into buffer and re-protect
        with open(temp_file.name, 'rb') as f:
            buffer = BytesIO(f.read())
        
        output_buffer, params = apply_docx_protection_buffer(
            buffer,
            "password2",
            edit_option="trackedChanges",
            return_protection_params=True
        )
        
        # Verify new protection replaced old
        assert params.edit_option == "trackedChanges", "Edit option should be updated"
        
        # Save and verify
        temp_file.seek(0)
        temp_file.write(output_buffer.read())
        temp_file.flush()
        
        protection_settings = get_docx_protection(temp_file.name)
        assert protection_settings.edit_option == "trackedChanges", "Final protection should be trackedChanges"

