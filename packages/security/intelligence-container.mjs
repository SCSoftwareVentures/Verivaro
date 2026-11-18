/** Fixed offline container profile. No user-controlled flags, mounts, environment or image tags.
 * Invoke on a dedicated rootless runtime host only, never through an API Docker socket.
 */
export function intelligenceContainerArgs(imageId){
 if(typeof imageId!=='string'||!/^sha256:[a-f0-9]{64}$/.test(imageId))throw Error('immutable local image ID required');
 return ['run','--rm','--interactive','--pull=never','--network=none','--read-only','--user=65532:65532','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--memory-swap=128m','--cpus=0.5','--pids-limit=32','--log-driver=none','--env=HTTP_PROXY=','--env=HTTPS_PROXY=','--env=ALL_PROXY=','--env=NO_PROXY=','--env=http_proxy=','--env=https_proxy=','--env=all_proxy=','--env=no_proxy=',imageId];
}
