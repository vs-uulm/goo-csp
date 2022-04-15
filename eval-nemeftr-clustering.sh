#!/usr/bin/env bash
#
# Clustering of segments on similarity without ground truth from CSP and Netzob segments.

#input="input/maxdiff-fromOrig/*-100*.pcap"
#input="input/maxdiff-fromOrig/ntp_SMIA-20111010_deduped-9995-10000_maxdiff-1100.pcap"
#input="input/maxdiff-fromOrig/smb_SMIA20111010-one-rigid1_maxdiff-100*.pcap"
#input="input/maxdiff-fromOrig/dhcp_SMIA2011101X-filtered_maxdiff-1000.pcap"
#input="input/wlan-beacons-priv_maxdiff-100*.pcapng"

#input="input/awdl-filtered_maxdiff-100.pcap input/awdl-filtered_maxdiff-250.pcap input/awdl-filtered_maxdiff-350.pcap input/awdl-filtered_maxdiff-500.pcap input/awdl-filtered.pcap"
input="input/ari_syslog_corpus_maxdiff-99.pcapng input/ari_syslog_corpus_maxdiff-999.pcapng"


segmenters="csp.py netzob_ftr.py"
L2PROTOS="input/awdl-* input/au-* input/wlan-beacons-*"
L1PROTOS="input/ari_*"
prefix="cft"

cftnpad="350"
for f in reports/${prefix}-* ; do
  if [ -e "$f" ] ; then
    cftnext=$(expr 1 + $(ls -d reports/${prefix}-* | sed "s/^.*${prefix}-\([0-9]*\)-.*$/\1/" | sort | tail -1))
    cftnpad=$(printf "%03d" ${cftnext})
  fi
  break
done
currcomm=$(git log -1 --format="%h")
report=reports/${prefix}-${cftnpad}-clustering-${currcomm}
mkdir ${report}

for seg in ${segmenters} ; do
      pids=()
      for fn in ${input} ; do
          optargs=""
          for proto in ${L2PROTOS} ; do
            if [[ "${fn}" == ${proto} ]] ; then
              # replace
              optargs="-rl2"
            fi
          done
          for proto in ${L1PROTOS} ; do
            if [[ "${fn}" == ${proto} ]] ; then
              # replace
              optargs="-rl1"
            fi
          done
          if [[ "${seg}" == "csp.py" ]] ; then
            optargs="${optargs} -f"
          fi
          bn=$(basename -- ${fn})
          strippedname="${bn%.*}"

          python src/${seg} ${optargs} ${fn} # >> "${report}/${strippedname}.log" &
          pids+=( $! )
      done

#      for pid in "${pids[@]}"; do
#              printf 'Waiting for %d...' "$pid"
#              wait $pid
#              echo 'done.'
#      done

      mkdir ${report}-${seg}
      for fn in ${input};
      do
          bn=$(basename -- ${fn})
          strippedname="${bn%.*}"
          mv reports/${strippedname}* ${report}-${seg}/
      done
done

python sub/nemere/src/transform_cluster-statistics.py
mv reports/*.csv ${report}/

spd-say "Bin fertig!"


# For testing BIDE:
# python src/nemeftr_cluster-segments.py -prt bide -f zerocharPCAmocoSF input/maxdiff-fromOrig/ntp_SMIA-20111010_maxdiff-100.pcap
