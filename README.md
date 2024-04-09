# Introduction

SPAN (SELinux Policy Analysis Notebook) is a small library designed to make using SETools 4 simple in a Jupyter notebook.

Using SETools within Jupyter notebook is an amazingly productive way to do policy analysis. It becomes simple to keep
notes alongside any queries you do or, almost more importantly, write simple scripts that allow you to do more powerful
policy analysis.

![SPAN Screenshot](/images/screenshot.png?raw=true "SPAN Screenshot")

Jupyter notebooks are an interactive environment that lets you write text (in Markdown) and code together. What's
powerful is that the code is executable within the document itself. That let's you
write queries and text together at the same time. You can get a feel for what's possible in this awesome notebook on
[Regex Golf from XKCD](http://nbviewer.jupyter.org/url/norvig.com/ipython/xkcd1313.ipynb). There is also the more
official (and boring) [introduction](https://jupyter-notebook-beginner-guide.readthedocs.io/en/latest/).

# Installation

SPAN is typically tested on newer Fedora versions and on RHEL 9 and rebuilds such as Rocky Linux.

SPAN is pure Python and supports Python 3 only.

## SETools Requirement

SPAN requires setools 4 along with the Python bindings. The easiest way to handle this is to install setools from the RPMs and then bring those into a virtual environment. You can do this as follows:

```
$ sudo dnf install setools
$ python -m venv --system-site-packages venv
$ source venv/bin/active
```

## Installing SPAN

You can install SPAN with:

```
$ python -m pip install .
```

## MacOS Support

Also note, that this all installs and works on MacOS as well. You will have to install libsepol and SETools from
source, but if you have a working development environment that is not difficult. Just make certain that you
use master from SELinux userspace (https://github.com/SELinuxProject/selinux) and SETools.

1. You must install coreutils and pandoc. We recommend using Home Brew (https://github.com/Homebrew/brew) to install these.
1. You must install userspace SELinux using specific parameters to make so the library ends up in the correct place.

```
brew install coreutils pandoc
# cd you your SELinux checkout
cd libsepol
sudo make DESTDIR=/usr/local PREFIX=/usr/local install
```

After this, you should install setools 4. Then follow the instructions described above in the Installation section.

# Getting Started

Go to examples and start Jupyter notebook: e.g., jupyter-notebook. This will open a browser window listing the
 contents of the directory. From there you can explore the example notebooks (start with SPAN Example).
