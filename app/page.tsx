import { AtlasWorkbench } from "@/components/AtlasWorkbench";
import {
  fetchNetworkExplorerSnapshot,
  mapNetworkSnapshotToWorkbenchProps,
} from "@/lib/server/network-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export default async function HomePage() {
  const snapshot = await fetchNetworkExplorerSnapshot();
  const props = mapNetworkSnapshotToWorkbenchProps(snapshot);

  return <AtlasWorkbench {...props} />;
}
