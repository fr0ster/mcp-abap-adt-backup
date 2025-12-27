import type { BackupTreeNode } from '../types';

function getPackageName(node: BackupTreeNode): string | undefined {
  const config = node.config as Record<string, unknown> | undefined;
  const name = config?.packageName;
  return typeof name === 'string' && name.trim()
    ? name.toUpperCase()
    : undefined;
}

function collectObjectNodes(node: BackupTreeNode, out: BackupTreeNode[]): void {
  if (node.type || node.adtType) {
    out.push(node);
  }
  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      collectObjectNodes(child, out);
    }
  }
}

export function groupTreeByPackage(root: BackupTreeNode): BackupTreeNode {
  if (!root.children || root.children.length === 0) {
    return root;
  }

  const rootName = root.name.toUpperCase();
  const objectNodes: BackupTreeNode[] = [];
  for (const child of root.children) {
    collectObjectNodes(child, objectNodes);
  }

  const packageNodes = new Map<string, BackupTreeNode>();
  const rootObjects: BackupTreeNode[] = [];

  for (const node of objectNodes) {
    const packageName = getPackageName(node);
    if (packageName && packageName !== rootName) {
      let packageNode = packageNodes.get(packageName);
      if (!packageNode) {
        packageNode = {
          name: packageName,
          adtType: 'DEVC/K',
          restoreStatus: 'not-implemented',
          children: [],
        };
        packageNodes.set(packageName, packageNode);
      }
      packageNode.children = [...(packageNode.children || []), node];
      continue;
    }
    rootObjects.push(node);
  }

  return {
    ...root,
    children: [...packageNodes.values(), ...rootObjects],
  };
}
