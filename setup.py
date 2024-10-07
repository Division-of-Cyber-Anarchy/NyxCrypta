from setuptools import setup, find_packages

with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='NyxCrypta',
    version='1.0.1',
    author='DCA (Malic1tus, Calypt0sis, ViraL0x, NyxCrypta)',
    author_email='malic1tus@proton.me',
    description='Outil de cryptographie basé sur RSA et AES',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Division-of-Cyber-Anarchy/NyxCrypta',
    packages=find_packages(),
    install_requires=[
        'cryptography>=3.3.2',  # Spécifier une version stable minimale
        'argon2-cffi>=20.1.0',  # Ajout de la dépendance correcte
        'cffi>=1.0.0',          # Prendre en compte la dépendance de argon2-cffi
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.10',
    entry_points={
        'console_scripts': [
            'nyxcrypta=nyxcrypta.nyxcrypta:main',
        ],
    },
)
