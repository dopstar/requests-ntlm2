from setuptools import setup


version = "6.2.9"
url = "https://github.com/dopstar/requests-ntlm2"

if "a" in version:
    dev_status = "3 - Alpha"
elif "b" in version:
    dev_status = "4 - Beta"
else:
    dev_status = "5 - Production/Stable"


with open("README.md") as fd:
    long_description = fd.read()


requirements = [
    "requests>=2.0.0",
    "ntlm-auth>=1.0.2",
    "cryptography>=1.3",
    "six>=1.10",
]

testing_requirements = [
    "flask",
    "pytest",
    "pytest-cov",
    "wheel",
    "codecov",
    "coverage",
    "mock",
    "faker",
    "trustme",
]

linting_requirements = [
    "flake8",
    "bandit==1.6.2; python_version == '2.7'",
    "bandit; python_version != '2.7'",
    "flake8-isort",
    "flake8-quotes",
]


setup(
    name="requests_ntlm2",
    version=version,
    packages=["requests_ntlm2"],
    install_requires=requirements,
    tests_require=testing_requirements,
    extras_require={"testing": testing_requirements, "linting": linting_requirements},
    author="Mkhanyisi Madlavana",
    author_email="mmadlavana@gmail.com",
    url=url,
    download_url="{url}/archive/{version}.tar.gz".format(url=url, version=version),
    description=(
        "The HTTP NTLM proxy and/or server authentication library."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="ISC",
    keywords=["NTLM", "requests", "proxy", "authorization", "NTLM dance"],
    package_dir={"requests_ntlm2": "requests_ntlm2"},
    classifiers=[
        "Development Status :: {0}".format(dev_status),
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Topic :: Software Development :: Version Control :: Git",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
)
