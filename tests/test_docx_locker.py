import pytest
import shutil
from tempfile import NamedTemporaryFile
from docx_locker import apply_docx_protection, get_docx_protection


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
        'cryptProviderType': 'rsaAES',
        'cryptAlgorithmClass': 'hash',
        'cryptAlgorithmType': 'typeAny',
        'cryptAlgorithmSid': '14',
        'cryptSpinCount': '100000',
        'hash': 'Zny9LoLNIRJagio+ZT7YYLp4WKoieHQx7ggU0hQ795TjtK05LUATM3/R4CXLv6+BnWejpDbdkbtKL9HdfdWOnw==',
        'salt': 'SKP/sgkziAF2G67DFMGFuQ=='
    }


def test_get_docx_protection_with_protected_doc(known_word_protection):
    case = get_docx_protection(known_word_protection['doc_path'])
    assert case['edit_option'] == known_word_protection['edit_option'], "Edit option does not match expected value"
    assert case['enforce_option'] == known_word_protection['enforce_option'], "Enforce option does not match expected value"
    assert case['cryptProviderType'] == known_word_protection['cryptProviderType'], "Crypt provider type does not match expected value"
    assert case['cryptAlgorithmClass'] == known_word_protection['cryptAlgorithmClass'], "Crypt algorithm class does not match expected value"
    assert case['cryptAlgorithmType'] == known_word_protection['cryptAlgorithmType'], "Crypt algorithm type does not match expected value"
    assert case['cryptAlgorithmSid'] == known_word_protection['cryptAlgorithmSid'], "Crypt algorithm SID does not match expected value"
    assert case['cryptSpinCount'] == known_word_protection['cryptSpinCount'], "Crypt spin count does not match expected value"
    assert case['hash'] == known_word_protection['hash'], "Hash does not match expected value"
    assert case['salt'] == known_word_protection['salt'], "Salt does not match expected value"


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
        assert protection_settings['edit_option'] == "trackedChanges", "Edit option should be TrackedChanges"
        assert protection_settings['enforce_option'] == '1', "Enforce option should be enabled (1)"
        assert protection_settings['cryptProviderType'] == 'rsaAES', "Crypt provider type should be rsaAES"
        assert protection_settings['cryptProviderType'] != 'Zny9LoLNIRJagio+ZT7YYLp4WKoieHQx7ggU0hQ795TjtK05LUATM3/R4CXLv6+BnWejpDbdkbtKL9HdfdWOnw=='


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
        assert protection_settings['edit_option'] == "readOnly", "Edit option should be TrackedChanges"
        assert protection_settings['enforce_option'] == '1', "Enforce option should be enabled (1)"
        assert protection_settings['cryptProviderType'] == 'rsaAES', "Crypt provider type should still be rsaAES"


def test_apply_docx_protection_to_protected_doc_with_hash(protected_doc_path):
    # Use NamedTemporaryFile in the with statement to ensure it's properly cleaned up
    with NamedTemporaryFile(suffix=".docx", delete=True) as temp_file:
        # Copy the protected document to the temp file
        shutil.copyfile(protected_doc_path, temp_file.name)

        # Apply protection with a new password
        new_password = "updated_password"
        apply_docx_protection(temp_file.name, new_password, salt='ouz9XiaimAE4pO6OOtk28g==', edit_option="readOnly")

        # Retrieve the newly applied protection settings
        protection_settings = get_docx_protection(temp_file.name)

        assert protection_settings is not None, "Protection settings should not be None after reapplying protection"
        assert protection_settings['edit_option'] == "readOnly", "Edit option should be TrackedChanges"
        assert protection_settings['enforce_option'] == '1', "Enforce option should be enabled (1)"
        assert protection_settings['cryptProviderType'] == 'rsaAES', "Crypt provider type should still be rsaAES"
        assert protection_settings['salt'] == 'ouz9XiaimAE4pO6OOtk28g==', "Salt does not match expected value"
