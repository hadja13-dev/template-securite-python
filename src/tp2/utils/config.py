import logging

from dotenv import load_dotenv

# Cherche le fichier .env en remontant depuis ce fichier, jusqu'à la racine du projet.
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s : %(message)s",
)
logger = logging.getLogger("tp2")
