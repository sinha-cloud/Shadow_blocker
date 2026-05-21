import sys
import os
import logging

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("shadowblocker.main")

# Import the GUI app
try:
    from shadowblocker.gui import ShadowBlockerApp
except ImportError as e:
    logger.error(f"Failed to import ShadowBlockerApp. Ensure package structure is intact: {e}")
    sys.exit(1)

def main():
    logger.info("Initializing ShadowBlocker desktop application...")
    try:
        app = ShadowBlockerApp()
        app.mainloop()
    except Exception as e:
        logger.critical(f"Unhandled critical crash in main loop: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
