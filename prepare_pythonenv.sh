INCEPTIONENV_DIR="$HOME/inceptionenv"
if [ -d "$INCEPTIONENV_DIR" ] ; then
    echo "Directory $INCEPTIONENV_DIR already exists. Skipping python virtualenv creation."
    exit
fi

(virtualenv "$INCEPTIONENV_DIR" --python /usr/bin/python3
source "$INCEPTIONENV_DIR"/bin/activate
pip install -U pip
pip install -r requirements.txt)
