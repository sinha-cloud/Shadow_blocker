import os
import glob
import logging
from typing import List, Dict, Any

logger = logging.getLogger("shadowblocker.discovery")

def get_browser_user_data_paths() -> Dict[str, str]:
    """Returns standard Windows paths for browser user data."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        # Fallback to home AppData if LOCALAPPDATA is missing
        user_profile = os.environ.get("USERPROFILE", os.path.expanduser("~"))
        local_app_data = os.path.join(user_profile, "AppData", "Local")

    return {
        "Chrome": os.path.join(local_app_data, "Google", "Chrome", "User Data"),
        "Edge": os.path.join(local_app_data, "Microsoft", "Edge", "User Data"),
        "Brave": os.path.join(local_app_data, "BraveSoftware", "Brave-Browser", "User Data"),
    }

def discover_extensions_in_user_data(user_data_path: str, browser_name: str) -> List[Dict[str, str]]:
    """
    Scans a browser's User Data directory for all profiles and returns details of found extensions.
    Each extension is represented by a dictionary containing:
        - 'id': extension ID (folder name)
        - 'path': path to the active version folder containing manifest.json
        - 'browser': name of the browser
        - 'profile': name of the profile (e.g. 'Default', 'Profile 1')
    """
    discovered = []
    if not os.path.isdir(user_data_path):
        logger.debug(f"User data path for {browser_name} does not exist: {user_data_path}")
        return discovered

    try:
        subdirs = os.listdir(user_data_path)
    except Exception as e:
        logger.error(f"Failed to list user data directory {user_data_path}: {e}")
        return discovered

    # Scans any subdirectories that contain an 'Extensions' subfolder
    profile_candidates = []
    for d in subdirs:
        candidate_path = os.path.join(user_data_path, d)
        if os.path.isdir(candidate_path) and os.path.isdir(os.path.join(candidate_path, "Extensions")):
            profile_candidates.append(d)

    for profile in profile_candidates:
        extensions_dir = os.path.join(user_data_path, profile, "Extensions")
        if not os.path.isdir(extensions_dir):
            continue

        try:
            ext_ids = os.listdir(extensions_dir)
        except Exception as e:
            logger.error(f"Failed to list extensions directory {extensions_dir}: {e}")
            continue

        for ext_id in ext_ids:
            ext_id_path = os.path.join(extensions_dir, ext_id)
            if not os.path.isdir(ext_id_path):
                continue

            # Inside an extension ID folder, there are version folders (e.g. '1.0.0_0', '4.2.1_1')
            try:
                versions = os.listdir(ext_id_path)
            except Exception as e:
                logger.error(f"Failed to list versions in {ext_id_path}: {e}")
                continue

            for version in versions:
                version_path = os.path.join(ext_id_path, version)
                if not os.path.isdir(version_path):
                    continue

                manifest_path = os.path.join(version_path, "manifest.json")
                if os.path.isfile(manifest_path):
                    # Found an extension! We assume the latest version or just add it.
                    # Usually, there is only one active version folder, but if there are multiple,
                    # we can add them (or prioritize the latest). We'll add the version path.
                    discovered.append({
                        "id": ext_id,
                        "path": version_path,
                        "browser": browser_name,
                        "profile": profile,
                        "version": version
                    })
                    # Break after finding the version to avoid duplicates for same extension if multiple exist
                    break

    return discovered

def discover_all_browser_extensions() -> List[Dict[str, str]]:
    """Scans Chrome, Edge, and Brave and returns all discovered extensions."""
    all_discovered = []
    paths = get_browser_user_data_paths()
    for browser, path in paths.items():
        all_discovered.extend(discover_extensions_in_user_data(path, browser))
    return all_discovered

def scan_directory_recursively(root_dir: str) -> List[Dict[str, str]]:
    """
    Recursively scans any directory looking for folders containing 'manifest.json'.
    This is extremely useful for loading custom or unpacked extensions, e.g., our test folder.
    """
    discovered = []
    root_dir = os.path.normpath(root_dir)
    
    if not os.path.isdir(root_dir):
        return discovered

    # If the root folder itself has manifest.json, treat it as a single extension
    if os.path.isfile(os.path.join(root_dir, "manifest.json")):
        discovered.append({
            "id": os.path.basename(root_dir),
            "path": root_dir,
            "browser": "Custom / Unpacked",
            "profile": "N/A",
            "version": "Unknown"
        })
        return discovered

    # Walk the tree up to a reasonable depth (e.g., max 4 levels) to find manifest.json
    for root, dirs, files in os.walk(root_dir):
        if "manifest.json" in files:
            ext_id = os.path.basename(root)
            # If the parent folder is 'Extensions', the ID is actually the root folder name itself.
            # Otherwise we use the folder name containing manifest.json
            discovered.append({
                "id": ext_id,
                "path": root,
                "browser": "Custom / Unpacked",
                "profile": "N/A",
                "version": "Unknown"
            })
            # Once we find a manifest.json, we don't need to descend further into this subdirectory
            dirs.clear()  

    return discovered
