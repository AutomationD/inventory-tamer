from setuptools import setup

setup(
        name='inventory-tamer',
        version='0.1',
        py_modules=['inventory-tamer'],
        include_package_data=True,
        install_requires=[
            'click',
            'click-config',
            'python-nmap',
            'paramiko==2.00',
            'pyvmomi',
        ],
        entry_points='''
        [console_scripts]
        inventory-tamer=_inventory_tamer_:cli
        it=_inventory_tamer_:cli
    ''',
)