from setuptools import setup, find_packages

with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='nyxcrypta',
    version='1.5.0',
    author='DCA (Malic1tus, Calypt0sis, ViraL0x, NyxCrypta)',
    author_email='malic1tus@proton.me',
    description='Cryptography tool based on RSA and AES',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Division-of-Cyber-Anarchy/NyxCrypta',
    packages=find_packages(),
    install_requires=[
        'cryptography>=41.0.5',
        'argon2-cffi>=20.1.0',
        'cffi>=1.17.1',
        'tqdm>=4.67',
        'questionary>=2.0.1',
        'rich>=13.7.0',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'nyxcrypta=nyxcrypta.main:main',
        ],
    },
)
