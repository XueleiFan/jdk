/*
 * Copyright (c) 1999, 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package sun.security.ssl;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

import sun.security.action.GetIntegerAction;
import sun.security.ssl.SSLSessionImpl.ClientSession;

class SSLSessionContextImpl implements SSLSessionContext {
    private final static int DEFAULT_MAX_CACHE_SIZE = 20480;
    private final static int DEFAULT_TIMEOUT_SECONDS = 86400;   // 2 hours
    private static final int DEFAULT_CACHE_SIZE = getDefaultCacheSize();

    // Session cache which uses the session ID as key.  This cache is used for
    // two cases:
    // 1. cache the server stateful sessions, which could be used for session
    //    resumption.
    // 2. cache the client sessions, the session ID, returned by the
    //    SSLSession.getId() method, will is used to identify the session in
    //    application layer.  The session resumption in this implementation
    //    does not use this cache.
    private final SessionCache<SessionId, SSLSessionImpl> sessionIdCache;

    private SSLSessionContextImpl() {
        this.sessionIdCache =
                new SessionCache<>(DEFAULT_CACHE_SIZE, DEFAULT_TIMEOUT_SECONDS);
    }

    @Override
    public SSLSession getSession(byte[] sessionId) {
        if (sessionId == null) {
            throw new NullPointerException("session id cannot be null");
        }

        return sessionIdCache.get(new SessionId(sessionId));
    }

    @Override
    public Enumeration<byte[]> getIds() {
        ServerCacheVisitor scVisitor = new ServerCacheVisitor();
        sessionIdCache.accept(scVisitor);

        return scVisitor.getSessionIds();
    }

    @Override
    public void setSessionTimeout(int timeoutInSeconds)
            throws IllegalArgumentException {
        if (timeoutInSeconds < 0) {
            throw new IllegalArgumentException();
        }

        sessionIdCache.setTimeout(timeoutInSeconds);
    }

    @Override
    public int getSessionTimeout() {
        return (int)(sessionIdCache.timeoutMillis / 1000L);
    }

    @Override
    public void setSessionCacheSize(
            int cacheSize) throws IllegalArgumentException {
        if (cacheSize < 0) {
            throw new IllegalArgumentException();
        }

        sessionIdCache.setCapacity(cacheSize);
    }

    @Override
    public int getSessionCacheSize() {
        return sessionIdCache.maxCapacity;
    }

    // Cache a SSLSession
    //
    // Here we time the session from the time it cached instead of the
    // time it created, which is a little longer than the expected.
    void put(SSLSessionImpl session) {
        if (session.sessionId.isEmpty()) {
            throw new IllegalArgumentException();
        }

        sessionIdCache.put(session.getSessionId(), session);

        // Bind the session with the context.
        session.setSessionContext(this);
    }

    void remove(SSLSessionImpl session) {
        sessionIdCache.remove(session.sessionId);
    }

    private static final class ServerCacheVisitor
            implements CacheVisitor<SessionId, SSLSessionImpl> {
        ArrayList<byte[]> ids = null;

        @Override
        public void visit(java.util.Map<SessionId, SSLSessionImpl> map) {
            ids = new ArrayList<>(map.size());

            for (SessionId key : map.keySet()) {
                SSLSessionImpl value = map.get(key);
                if (value != null) {
                    ids.add(key.getId());
                }
            }
        }

        Enumeration<byte[]> getSessionIds() {
            return  ids != null ? Collections.enumeration(ids) :
                    Collections.emptyEnumeration();
        }
    }

    static class ServerSessionContext extends SSLSessionContextImpl {
        ServerSessionContext() {
            super();
        }
    }

    static class ClientSessionContext extends SSLSessionContextImpl {
        // Session cache which uses the service properties as key.  This cache
        // is internally used for the client session resumption request only.
        // The public APIs should use the super "sessionIdCache" instead, which
        // use session ID as the key.
        //
        // Note that the super.sessionIdCache and this serviceIdCache is not
        // synchronized, which is fine as the purpose of the two caches are
        // different.
        private final SessionCache<SessionId, ClientSession> serviceIdCache;

        ClientSessionContext() {
            super();
            this.serviceIdCache =
                new SessionCache<>(DEFAULT_CACHE_SIZE, DEFAULT_TIMEOUT_SECONDS);
        }

        @Override
        public void setSessionTimeout(int timeoutInSeconds)
                throws IllegalArgumentException {
            super.setSessionTimeout(timeoutInSeconds);
            serviceIdCache.setTimeout(timeoutInSeconds);
        }

        @Override
        public void setSessionCacheSize(int cacheSize)
                throws IllegalArgumentException {
            super.setSessionCacheSize(cacheSize);
            serviceIdCache.setCapacity(cacheSize);
        }

        @Override
        void put(SSLSessionImpl session) {
            super.put(session);

            ClientSession clientSession = (ClientSession)session;
            ClientSession replacedSession = serviceIdCache.put(
                    clientSession.clientHelloId, clientSession);
            if (replacedSession != null && replacedSession != clientSession) {
                clientSession.mergeTickets(replacedSession);
            }
        }

        @Override
        void remove(SSLSessionImpl session) {
            super.remove(session);
            serviceIdCache.remove(((ClientSession)session).clientHelloId);
        }

        // package-private method, used ONLY by client handshake
        ClientSession get(SessionId clientHelloId) {
            return serviceIdCache.get(clientHelloId);
        }
    }

    private static int getDefaultCacheSize() {
        try {
            int defaultCacheLimit = GetIntegerAction.privilegedGetProperty(
                    "javax.net.ssl.sessionCacheSize", DEFAULT_MAX_CACHE_SIZE);

            if (defaultCacheLimit >= 0) {
                return defaultCacheLimit;
            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning(
                    "invalid System Property javax.net.ssl.sessionCacheSize, " +
                    "use the default session cache size (" +
                    DEFAULT_MAX_CACHE_SIZE + ") instead");
            }
        } catch (Exception e) {
            // unlikely, log it for safe
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning(
                    "the System Property javax.net.ssl.sessionCacheSize is " +
                    "not available, use the default value (" +
                    DEFAULT_MAX_CACHE_SIZE + ") instead");
            }
        }

        return DEFAULT_MAX_CACHE_SIZE;
    }

    //
    // Session cache
    //
    private interface CacheVisitor<K, V> {
        void visit(Map<K, V> map);
    }

    private static class SessionCache<K, V> {
        private int maxCapacity;
        private long timeoutMillis;

        SoftCacheEntry<K, V> oldestEntry;
        SoftCacheEntry<K, V> newestEntry;

        private final ConcurrentHashMap<K, SoftCacheEntry<K, V>> cacheMap;
        private final ReferenceQueue<V> referenceQueue;

        private final ReentrantLock cacheLock = new ReentrantLock();

        SessionCache(int cacheLimit, int timeoutSeconds) {
            this.maxCapacity = cacheLimit;
            this.timeoutMillis = timeoutSeconds * 1000L;
            this.oldestEntry = null;
            this.newestEntry = null;
            this.cacheMap = new ConcurrentHashMap<>();
            this.referenceQueue = new ReferenceQueue<>();
        }

        private V get(K k) {
            SoftCacheEntry<K, V> entry = cacheMap.get(k);
            if (entry == null) {
                return null;
            }

            if (!entry.isValid()) {
                remove(entry);

                return null;
            }

            return entry.get();
        }

        private void accept(CacheVisitor<K, V> visitor) {
            visitor.visit(getCachedEntries());
        }

        private Map<K, V> getCachedEntries() {
            expungeExpiredEntries();
            Map<K, V> kvMap = new HashMap<>(cacheMap.size());

            for (SoftCacheEntry<K, V> entry : cacheMap.values()) {
                K k = entry.k;
                V v = entry.get();
                if (k != null && v != null) {
                    kvMap.put(k, v);
                }
            }

            return kvMap;
        }

        private void setTimeout(int timeoutInSeconds) {
            this.timeoutMillis =
                    timeoutInSeconds > 0 ? timeoutInSeconds * 1000L : 0L;
            cacheLock.lock();
            try {
                expungeExpiredEntries();
            }  finally {
                cacheLock.unlock();
            }
        }

        private void setCapacity(int cacheSize) {
            cacheLock.lock();
            try {
                expungeExpiredEntries();
                this.maxCapacity = cacheSize;
                while (cacheMap.size() > maxCapacity) {
                    remove(oldestEntry);
                }
            }  finally {
                cacheLock.unlock();
            }
        }

        private V put(K k, V v) {
            cacheLock.lock();
            try {
                long expirationTime = timeoutMillis == 0 ? 0 :
                        System.currentTimeMillis() + timeoutMillis;

                SoftCacheEntry<K, V> newEntry = new SoftCacheEntry<>(k, v,
                        expirationTime, referenceQueue, newestEntry);
                newestEntry = newEntry;
                SoftCacheEntry<K, V> oldEntry = cacheMap.put(k, newEntry);
                V returnedValue = null;
                if (oldEntry != null) {
                    if (oldEntry.isValid()) {
                        returnedValue = oldEntry.get();
                    }
                    unlink(oldEntry);
                }

                if (oldestEntry == null) {
                    oldestEntry = newEntry;
                }

                while (cacheMap.size() > maxCapacity) {
                    remove(oldestEntry);
                }

                return returnedValue;
            } finally {
                cacheLock.unlock();
            }
        }

        private void remove(K k) {
            SoftCacheEntry<K, V> removedEntry = cacheMap.remove(k);
            if (removedEntry != null) {
                unlink(removedEntry);
            }
        }

        private void remove(SoftCacheEntry<K, V> entry) {
            if (entry.k != null) {
                cacheMap.remove(entry.k);
            }

            unlink(entry);
        }

        private void expungeExpiredEntries() {
            cleanupQueue();
            if (timeoutMillis == 0) {
                return;
            }

            long currentTimeMillis = System.currentTimeMillis();
            while (oldestEntry != null &&
                    currentTimeMillis > oldestEntry.expirationTime) {
                remove(oldestEntry);
            }
        }

        private void cleanupQueue() {
            while (true) {
                @SuppressWarnings("unchecked")
                SoftCacheEntry<K, V> entry =
                        (SoftCacheEntry<K, V>)referenceQueue.poll();
                if (entry == null) {
                    break;
                }

                if (entry.k != null) {
                    remove(entry);
                }
            }
        }

        private void unlink(SoftCacheEntry<K, V> entry) {
            if (entry == oldestEntry) {
                oldestEntry = entry.next;
            }
            entry.unlink();
        }

        private static class SoftCacheEntry<K, V> extends SoftReference<V> {
            private K k;
            private long expirationTime;
            private SoftCacheEntry<K, V> prev;
            private SoftCacheEntry<K, V> next;

            SoftCacheEntry(K k, V v,
                    long expirationTime, ReferenceQueue<V> queue,
                   SoftCacheEntry<K, V> lastEntry) {
                super(v, queue);
                this.k = k;
                this.expirationTime = expirationTime;

                this.prev = lastEntry;
                this.next = null;
            }

            private boolean isValid() {
                if ((get() == null) || ((expirationTime != 0) &&
                        (System.currentTimeMillis() > expirationTime))) {

                    invalidate();
                    return false;
                }

                return true;
            }

            private void invalidate() {
                clear();
                k = null;
                expirationTime = -1;
            }

            private void unlink() {
                clear();
                k = null;
                expirationTime = -1;
                if (prev != null) {
                    prev.next = next;
                }

                if (next != null) {
                    next.prev = prev;
                }
            }
        }
    }
}
