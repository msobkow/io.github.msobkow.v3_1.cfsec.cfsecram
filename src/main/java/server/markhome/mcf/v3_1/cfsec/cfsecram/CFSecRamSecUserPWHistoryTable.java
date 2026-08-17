
// Description: Java 25 in-memory RAM DbIO implementation for SecUserPWHistory.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecUserPWHistoryTable in-memory RAM DbIO implementation
 *	for SecUserPWHistory.
 */
public class CFSecRamSecUserPWHistoryTable
	implements ICFSecSecUserPWHistoryTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecUserPWHistoryPKey,
				CFSecBuffSecUserPWHistory > dictByPKey
		= new HashMap< ICFSecSecUserPWHistoryPKey,
				CFSecBuffSecUserPWHistory >();
	private Map< CFSecBuffSecUserPWHistoryByUserIdxKey,
			CFSecBuffSecUserPWHistory > dictByUserIdx
		= new HashMap< CFSecBuffSecUserPWHistoryByUserIdxKey,
			CFSecBuffSecUserPWHistory >();
	private Map< CFSecBuffSecUserPWHistoryBySetStampIdxKey,
			CFSecBuffSecUserPWHistory > dictBySetStampIdx
		= new HashMap< CFSecBuffSecUserPWHistoryBySetStampIdxKey,
			CFSecBuffSecUserPWHistory >();
	private Map< CFSecBuffSecUserPWHistoryByReplacedStampIdxKey,
			CFSecBuffSecUserPWHistory > dictByReplacedStampIdx
		= new HashMap< CFSecBuffSecUserPWHistoryByReplacedStampIdxKey,
			CFSecBuffSecUserPWHistory >();

	public CFSecRamSecUserPWHistoryTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecUserPWHistory ensureRec(ICFSecSecUserPWHistory rec) {
		return (((CFSecBuffSecUserPWHistoryFactoryService)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory())).ensureRec(rec));
	}

	@Override
	public ICFSecSecUserPWHistory createSecUserPWHistory( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistory iBuff )
	{
		final String S_ProcName = "createSecUserPWHistory";
		
		CFSecBuffSecUserPWHistory Buff = (CFSecBuffSecUserPWHistory)ensureRec(iBuff);
		CFSecBuffSecUserPWHistoryPKey pkey = (CFSecBuffSecUserPWHistoryPKey)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newPKey());
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		pkey.setRequiredPWSetStamp( Buff.getRequiredPWSetStamp() );
		Buff.setRequiredSecUserId( pkey.getRequiredSecUserId() );
		Buff.setRequiredPWSetStamp( pkey.getRequiredPWSetStamp() );
		CFSecBuffSecUserPWHistoryByUserIdxKey keyUserIdx = (CFSecBuffSecUserPWHistoryByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecUserPWHistoryBySetStampIdxKey keySetStampIdx = (CFSecBuffSecUserPWHistoryBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newBySetStampIdxKey();
		keySetStampIdx.setRequiredPWSetStamp( Buff.getRequiredPWSetStamp() );

		CFSecBuffSecUserPWHistoryByReplacedStampIdxKey keyReplacedStampIdx = (CFSecBuffSecUserPWHistoryByReplacedStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByReplacedStampIdxKey();
		keyReplacedStampIdx.setRequiredPWReplacedStamp( Buff.getRequiredPWReplacedStamp() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecUserPWHistUserIdx",
				"SecUserPWHistUserIdx",
				keyUserIdx );
		}

		if( dictBySetStampIdx.containsKey( keySetStampIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecUserPWHistSetStampIdx",
				"SecUserPWHistSetStampIdx",
				keySetStampIdx );
		}

		if( dictByReplacedStampIdx.containsKey( keyReplacedStampIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecUserPWHistReplacedStampIdx",
				"SecUserPWHistReplacedStampIdx",
				keyReplacedStampIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUserIdx.put( keyUserIdx, Buff );

		dictBySetStampIdx.put( keySetStampIdx, Buff );

		dictByReplacedStampIdx.put( keyReplacedStampIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecUserPWHistory.CLASS_CODE) {
				CFSecBuffSecUserPWHistory retbuff = ((CFSecBuffSecUserPWHistory)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecUserPWHistory readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
		LocalDateTime PWSetStamp )
	{
		{	ICFLibKeyHash256 testSecUserId = SecUserId;
			if (testSecUserId == null) {
				return( null );
			}
		}
		{	LocalDateTime testPWSetStamp = PWSetStamp;
			if (testPWSetStamp == null) {
				return( null );
			}
		}
		CFSecBuffSecUserPWHistoryPKey key = (CFSecBuffSecUserPWHistoryPKey)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newPKey());
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredPWSetStamp( PWSetStamp );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecUserPWHistory readDerived( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistoryPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readDerived";
		CFSecBuffSecUserPWHistoryPKey key = (CFSecBuffSecUserPWHistoryPKey)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newPKey());
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		key.setRequiredPWSetStamp( PKey.getRequiredPWSetStamp() );
		ICFSecSecUserPWHistory buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWHistory lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistoryPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.lockDerived";
		CFSecBuffSecUserPWHistoryPKey key = (CFSecBuffSecUserPWHistoryPKey)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newPKey());
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		key.setRequiredPWSetStamp( PKey.getRequiredPWSetStamp() );
		ICFSecSecUserPWHistory buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWHistory[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecUserPWHistory.readAllDerived";
		ICFSecSecUserPWHistory[] retList = new ICFSecSecUserPWHistory[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecUserPWHistory > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecUserPWHistory readDerivedByUserIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readDerivedByUserIdx";
		CFSecBuffSecUserPWHistoryByUserIdxKey key = (CFSecBuffSecUserPWHistoryByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByUserIdxKey();

		key.setRequiredSecUserId( SecUserId );
		ICFSecSecUserPWHistory buff;
		if( dictByUserIdx.containsKey( key ) ) {
			buff = dictByUserIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWHistory readDerivedBySetStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime PWSetStamp )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readDerivedBySetStampIdx";
		CFSecBuffSecUserPWHistoryBySetStampIdxKey key = (CFSecBuffSecUserPWHistoryBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newBySetStampIdxKey();

		key.setRequiredPWSetStamp( PWSetStamp );
		ICFSecSecUserPWHistory buff;
		if( dictBySetStampIdx.containsKey( key ) ) {
			buff = dictBySetStampIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWHistory readDerivedByReplacedStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime PWReplacedStamp )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readDerivedByReplacedStampIdx";
		CFSecBuffSecUserPWHistoryByReplacedStampIdxKey key = (CFSecBuffSecUserPWHistoryByReplacedStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByReplacedStampIdxKey();

		key.setRequiredPWReplacedStamp( PWReplacedStamp );
		ICFSecSecUserPWHistory buff;
		if( dictByReplacedStampIdx.containsKey( key ) ) {
			buff = dictByReplacedStampIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWHistory readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
		LocalDateTime PWSetStamp )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readDerivedByIdIdx() ";
		CFSecBuffSecUserPWHistoryPKey key = (CFSecBuffSecUserPWHistoryPKey)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newPKey());
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredPWSetStamp( PWSetStamp );
		ICFSecSecUserPWHistory buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWHistory readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
		LocalDateTime PWSetStamp )
	{
		CFSecBuffSecUserPWHistoryPKey key = (CFSecBuffSecUserPWHistoryPKey)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newPKey());
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredPWSetStamp( PWSetStamp );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecUserPWHistory readRec( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistoryPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readRec";
		ICFSecSecUserPWHistory buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUserPWHistory.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWHistory lockRec( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistoryPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecUserPWHistory buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUserPWHistory.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWHistory[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readAllRec";
		ICFSecSecUserPWHistory buff;
		ArrayList<ICFSecSecUserPWHistory> filteredList = new ArrayList<ICFSecSecUserPWHistory>();
		ICFSecSecUserPWHistory[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWHistory.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserPWHistory[0] ) );
	}

	/**
	 *	Read a page of all the specific SecUserPWHistory buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecUserPWHistory instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecUserPWHistory[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecUserId,
		LocalDateTime priorPWSetStamp )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecUserPWHistory readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
		LocalDateTime PWSetStamp )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readRecByIdIdx() ";
		ICFSecSecUserPWHistory buff = readDerivedByIdIdx( Authorization,
			SecUserId,
			PWSetStamp );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWHistory.CLASS_CODE ) ) {
			return( (ICFSecSecUserPWHistory)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUserPWHistory readRecByUserIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readRecByUserIdx() ";
		ICFSecSecUserPWHistory buff = readDerivedByUserIdx( Authorization,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWHistory.CLASS_CODE ) ) {
			return( (ICFSecSecUserPWHistory)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUserPWHistory readRecBySetStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime PWSetStamp )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readRecBySetStampIdx() ";
		ICFSecSecUserPWHistory buff = readDerivedBySetStampIdx( Authorization,
			PWSetStamp );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWHistory.CLASS_CODE ) ) {
			return( (ICFSecSecUserPWHistory)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUserPWHistory readRecByReplacedStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime PWReplacedStamp )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistory.readRecByReplacedStampIdx() ";
		ICFSecSecUserPWHistory buff = readDerivedByReplacedStampIdx( Authorization,
			PWReplacedStamp );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWHistory.CLASS_CODE ) ) {
			return( (ICFSecSecUserPWHistory)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUserPWHistory updateSecUserPWHistory( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistory iBuff )
	{
		CFSecBuffSecUserPWHistory Buff = (CFSecBuffSecUserPWHistory)ensureRec(iBuff);
		CFSecBuffSecUserPWHistoryPKey pkey = (CFSecBuffSecUserPWHistoryPKey)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newPKey());
		pkey = (CFSecBuffSecUserPWHistoryPKey)Buff.getPKey();
		CFSecBuffSecUserPWHistory existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecUserPWHistory",
				"Existing record not found",
				"Existing record not found",
				"SecUserPWHistory",
				"SecUserPWHistory",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecUserPWHistory",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecUserPWHistoryByUserIdxKey existingKeyUserIdx = (CFSecBuffSecUserPWHistoryByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByUserIdxKey();
		existingKeyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecUserPWHistoryByUserIdxKey newKeyUserIdx = (CFSecBuffSecUserPWHistoryByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByUserIdxKey();
		newKeyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecUserPWHistoryBySetStampIdxKey existingKeySetStampIdx = (CFSecBuffSecUserPWHistoryBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newBySetStampIdxKey();
		existingKeySetStampIdx.setRequiredPWSetStamp( existing.getRequiredPWSetStamp() );

		CFSecBuffSecUserPWHistoryBySetStampIdxKey newKeySetStampIdx = (CFSecBuffSecUserPWHistoryBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newBySetStampIdxKey();
		newKeySetStampIdx.setRequiredPWSetStamp( Buff.getRequiredPWSetStamp() );

		CFSecBuffSecUserPWHistoryByReplacedStampIdxKey existingKeyReplacedStampIdx = (CFSecBuffSecUserPWHistoryByReplacedStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByReplacedStampIdxKey();
		existingKeyReplacedStampIdx.setRequiredPWReplacedStamp( existing.getRequiredPWReplacedStamp() );

		CFSecBuffSecUserPWHistoryByReplacedStampIdxKey newKeyReplacedStampIdx = (CFSecBuffSecUserPWHistoryByReplacedStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByReplacedStampIdxKey();
		newKeyReplacedStampIdx.setRequiredPWReplacedStamp( Buff.getRequiredPWReplacedStamp() );

		// Check unique indexes

		if( ! existingKeyUserIdx.equals( newKeyUserIdx ) ) {
			if( dictByUserIdx.containsKey( newKeyUserIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecUserPWHistory",
					"SecUserPWHistUserIdx",
					"SecUserPWHistUserIdx",
					newKeyUserIdx );
			}
		}

		if( ! existingKeySetStampIdx.equals( newKeySetStampIdx ) ) {
			if( dictBySetStampIdx.containsKey( newKeySetStampIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecUserPWHistory",
					"SecUserPWHistSetStampIdx",
					"SecUserPWHistSetStampIdx",
					newKeySetStampIdx );
			}
		}

		if( ! existingKeyReplacedStampIdx.equals( newKeyReplacedStampIdx ) ) {
			if( dictByReplacedStampIdx.containsKey( newKeyReplacedStampIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecUserPWHistory",
					"SecUserPWHistReplacedStampIdx",
					"SecUserPWHistReplacedStampIdx",
					newKeyReplacedStampIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFSecBuffSecUserPWHistoryPKey, CFSecBuffSecUserPWHistory > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUserIdx.remove( existingKeyUserIdx );
		dictByUserIdx.put( newKeyUserIdx, Buff );

		dictBySetStampIdx.remove( existingKeySetStampIdx );
		dictBySetStampIdx.put( newKeySetStampIdx, Buff );

		dictByReplacedStampIdx.remove( existingKeyReplacedStampIdx );
		dictByReplacedStampIdx.put( newKeyReplacedStampIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecUserPWHistory( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistory iBuff )
	{
		final String S_ProcName = "CFSecRamSecUserPWHistoryTable.deleteSecUserPWHistory() ";
		CFSecBuffSecUserPWHistory Buff = (CFSecBuffSecUserPWHistory)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecUserPWHistoryPKey pkey = (CFSecBuffSecUserPWHistoryPKey)(Buff.getPKey());
		CFSecBuffSecUserPWHistory existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecUserPWHistory",
				pkey );
		}
		CFSecBuffSecUserPWHistoryByUserIdxKey keyUserIdx = (CFSecBuffSecUserPWHistoryByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecUserPWHistoryBySetStampIdxKey keySetStampIdx = (CFSecBuffSecUserPWHistoryBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newBySetStampIdxKey();
		keySetStampIdx.setRequiredPWSetStamp( existing.getRequiredPWSetStamp() );

		CFSecBuffSecUserPWHistoryByReplacedStampIdxKey keyReplacedStampIdx = (CFSecBuffSecUserPWHistoryByReplacedStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByReplacedStampIdxKey();
		keyReplacedStampIdx.setRequiredPWReplacedStamp( existing.getRequiredPWReplacedStamp() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecUserPWHistoryPKey, CFSecBuffSecUserPWHistory > subdict;

		dictByPKey.remove( pkey );

		dictByUserIdx.remove( keyUserIdx );

		dictBySetStampIdx.remove( keySetStampIdx );

		dictByReplacedStampIdx.remove( keyReplacedStampIdx );

	}
	@Override
	public void deleteSecUserPWHistoryByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
		LocalDateTime PWSetStamp )
	{
		CFSecBuffSecUserPWHistoryPKey key = (CFSecBuffSecUserPWHistoryPKey)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newPKey());
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredPWSetStamp( PWSetStamp );
		deleteSecUserPWHistoryByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserPWHistoryByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistoryPKey PKey )
	{
		CFSecBuffSecUserPWHistoryPKey key = (CFSecBuffSecUserPWHistoryPKey)(schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newPKey());
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		key.setRequiredPWSetStamp( PKey.getRequiredPWSetStamp() );
		CFSecBuffSecUserPWHistoryPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecUserPWHistory cur;
		LinkedList<CFSecBuffSecUserPWHistory> matchSet = new LinkedList<CFSecBuffSecUserPWHistory>();
		Iterator<CFSecBuffSecUserPWHistory> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPWHistory> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPWHistory)(schema.getTableSecUserPWHistory().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredPWSetStamp() ));
			deleteSecUserPWHistory( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserPWHistoryByUserIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecUserId )
	{
		CFSecBuffSecUserPWHistoryByUserIdxKey key = (CFSecBuffSecUserPWHistoryByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecUserPWHistoryByUserIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserPWHistoryByUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistoryByUserIdxKey argKey )
	{
		CFSecBuffSecUserPWHistory cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserPWHistory> matchSet = new LinkedList<CFSecBuffSecUserPWHistory>();
		Iterator<CFSecBuffSecUserPWHistory> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPWHistory> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPWHistory)(schema.getTableSecUserPWHistory().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredPWSetStamp() ));
			deleteSecUserPWHistory( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserPWHistoryBySetStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime argPWSetStamp )
	{
		CFSecBuffSecUserPWHistoryBySetStampIdxKey key = (CFSecBuffSecUserPWHistoryBySetStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newBySetStampIdxKey();
		key.setRequiredPWSetStamp( argPWSetStamp );
		deleteSecUserPWHistoryBySetStampIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserPWHistoryBySetStampIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistoryBySetStampIdxKey argKey )
	{
		CFSecBuffSecUserPWHistory cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserPWHistory> matchSet = new LinkedList<CFSecBuffSecUserPWHistory>();
		Iterator<CFSecBuffSecUserPWHistory> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPWHistory> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPWHistory)(schema.getTableSecUserPWHistory().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredPWSetStamp() ));
			deleteSecUserPWHistory( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserPWHistoryByReplacedStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime argPWReplacedStamp )
	{
		CFSecBuffSecUserPWHistoryByReplacedStampIdxKey key = (CFSecBuffSecUserPWHistoryByReplacedStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWHistory().newByReplacedStampIdxKey();
		key.setRequiredPWReplacedStamp( argPWReplacedStamp );
		deleteSecUserPWHistoryByReplacedStampIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserPWHistoryByReplacedStampIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserPWHistoryByReplacedStampIdxKey argKey )
	{
		CFSecBuffSecUserPWHistory cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserPWHistory> matchSet = new LinkedList<CFSecBuffSecUserPWHistory>();
		Iterator<CFSecBuffSecUserPWHistory> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPWHistory> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPWHistory)(schema.getTableSecUserPWHistory().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredPWSetStamp() ));
			deleteSecUserPWHistory( Authorization, cur );
		}
	}
}
