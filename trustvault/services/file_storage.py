import mimetypes
import os
from pathlib import Path
import uuid
from typing import Set, Tuple
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename


class FileStorageError(Exception):
    """Base exception for file storage failures."""
    pass


def is_allowed_file(filename: str, allowed_extensions: Set[str]) -> bool:
    """Check if file has an allowed extension and no dangerous null bytes."""
    if not filename or "\x00" in filename:
        return False
    parts = filename.rsplit(".", 1)
    if len(parts) != 2:
        return False
    ext = parts[1].lower()
    return ext in allowed_extensions


def save_uploaded_file(
    file_storage: FileStorage,
    upload_folder: Path,
    allowed_extensions: Set[str],
) -> Tuple[str, str, int, str]:
    """Securely save an uploaded file to disk.
    
    Protections:
    1. Replaces disk filename with random UUID to prevent collisions & traversal.
    2. Validates extension against strict whitelist.
    3. Resolves absolute path and verifies directory confinement.
    4. Detects/normalizes MIME type.
    
    Returns:
        (uuid_name, sanitized_original_filename, file_size_bytes, mime_type)
    """
    if not file_storage or not file_storage.filename:
        raise FileStorageError("No file provided.")

    original_name = secure_filename(file_storage.filename)
    if not original_name:
        raise FileStorageError("Invalid filename.")

    if not is_allowed_file(original_name, allowed_extensions):
        raise FileStorageError(
            f"File type not permitted. Allowed extensions: {', '.join(sorted(allowed_extensions))}"
        )

    # Ensure upload directory exists
    upload_folder = Path(upload_folder).resolve()
    upload_folder.mkdir(parents=True, exist_ok=True)

    # Generate random UUID key
    disk_uuid = str(uuid.uuid4())
    disk_filename = f"{disk_uuid}.dat"
    target_path = (upload_folder / disk_filename).resolve()

    # Path traversal verification
    try:
        common = os.path.commonpath([str(target_path), str(upload_folder)])
        if common != str(upload_folder):
            raise FileStorageError("Path traversal attempt detected.")
    except ValueError:
        raise FileStorageError("Invalid storage destination.")

    # Save to disk
    file_storage.save(str(target_path))
    file_size = target_path.stat().st_size

    # Determine MIME type
    mime_type, _ = mimetypes.guess_type(original_name)
    if not mime_type:
        mime_type = file_storage.content_type or "application/octet-stream"

    return disk_uuid, original_name, file_size, mime_type


def get_secure_file_path(uuid_name: str, upload_folder: Path) -> Path:
    """Resolve and verify absolute file path for a stored document."""
    upload_folder = Path(upload_folder).resolve()
    # UUID check
    clean_uuid = secure_filename(uuid_name)
    target_path = (upload_folder / f"{clean_uuid}.dat").resolve()

    # Confine to upload_folder
    try:
        common = os.path.commonpath([str(target_path), str(upload_folder)])
        if common != str(upload_folder):
            raise FileStorageError("Invalid file path.")
    except ValueError:
        raise FileStorageError("Invalid file path.")

    if not target_path.is_file():
        raise FileStorageError("File not found on storage disk.")

    return target_path


def delete_stored_file(uuid_name: str, upload_folder: Path) -> bool:
    """Safely delete stored file from disk."""
    try:
        file_path = get_secure_file_path(uuid_name, upload_folder)
        if file_path.exists():
            file_path.unlink()
            return True
    except FileStorageError:
        pass
    return False
