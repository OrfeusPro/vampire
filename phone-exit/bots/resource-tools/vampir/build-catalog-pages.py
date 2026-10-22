"""Deploy catalogue UI assets. Data remains in existing SHA-linked loot/atlas outputs."""
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    maps = root / 'maps'
    routes = {
        'catalog-nav.js': 'catalog-nav.js', 'catalog-nav.css': 'catalog-nav.css',
        'catalog.css': 'catalog.css', 'catalog-data.js': 'catalog-data.js',
        'catalog-class-model.js': 'catalog-class-model.js', 'atlas-locale.js': 'atlas-locale.js',
        'collections.html': 'collections/index.html', 'collections.js': 'collections/collections.js',
        'collections.css': 'collections/collections.css', 'collections-model.js': 'collections/collections-model.js',
        'attributes.html': 'attributes/index.html', 'attributes.js': 'attributes/attributes.js',
        'attributes.css': 'attributes/attributes.css', 'attributes-model.js': 'attributes/attributes-model.js',
        'skill-card.js': 'atlas/skill-card.js', 'skill-card.css': 'atlas/skill-card.css',
        'monster-card.js': 'atlas/monster-card.js',
        'monster-card.css': 'atlas/monster-card.css',
        'monsters-catalog.html': 'atlas/monsters.html', 'monsters-catalog.js': 'atlas/monsters-catalog.js',
        'monsters-catalog-model.js': 'atlas/monsters-catalog-model.js',
        'skills-catalog.html': 'atlas/skills.html', 'skills-catalog.js': 'atlas/skills-catalog.js',
        'skills-catalog-model.js': 'atlas/skills-catalog-model.js',
        'items-catalog.html': 'loot/items.html', 'items-catalog.js': 'loot/items-catalog.js',
        'items-catalog-model.js': 'loot/items-catalog-model.js',
    }
    for source, target in routes.items():
        path = maps / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((HERE / source).read_bytes())
    (maps / 'loot/books.html').write_bytes((HERE / 'items-catalog.html').read_bytes())
    import runpy
    runpy.run_path(str(HERE / 'build-catalog-classes.py'))['main'](root)
    runpy.run_path(str(HERE / 'build-skill-catalog-meta.py'))['main'](root)
    runpy.run_path(str(HERE / 'build-collections.py'))['main'](root)
    runpy.run_path(str(HERE / 'build-attributes.py'))['main'](root)
    return routes


if __name__ == '__main__':
    main()
